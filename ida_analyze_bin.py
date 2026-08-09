#!/usr/bin/env python3
"""Validate x86 binaries and execute the deterministic/LLM/agent analysis DAG."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path

import yaml

import agent_runner
from analysis_config import AnalysisConfigError, resolve_analysis_config, validated_tag
from analysis_planner import (
    AnalysisPlanError,
    ExecutionPlan,
    load_config,
    parse_config_document,
    validate_artifact_path,
)
from analysis_planner import (
    build_execution_plan as _build_execution_plan,
)
from binary_format import BinaryFormatError, validate_binary
from ida_analyze_util import signature_matches
from ida_skill_preprocessor import PreprocessorError, preprocess_skill, preprocess_skill_with_llm
from process_reporter import ConsoleReporter, NullReporter, ProgressEvent

PLATFORMS = ("windows", "linux")
ANALYSIS_STAGES = ("history", "deterministic", "llm", "agent")


class AnalysisRunError(RuntimeError):
    pass


def parse_config(config_path, config_document=None):
    if config_document is not None:
        return parse_config_document(config_document)
    return load_config(config_path)[1]


def _skill_runs_on_platform(skill, platform):
    return skill.get("platform") in {None, platform}


def resolve_artifact_path(binary_dir, artifact_path, platform):
    filename = validate_artifact_path(artifact_path, "artifact", platform)
    module_root = Path(binary_dir).resolve()
    result = (module_root / filename).resolve()
    if result.parent != module_root:
        raise ValueError(f"Artifact path escapes module directory: {artifact_path}")
    return str(result)


def expand_expected_paths(binary_dir, paths, platform):
    return [resolve_artifact_path(binary_dir, path, platform) for path in paths]


def expand_skill_output_paths(binary_dir, skill, platform):
    common = list(skill.get("expected_output", []) or [])
    common.extend(skill.get(f"expected_output_{platform}", []) or [])
    required = expand_expected_paths(binary_dir, common, platform)
    optional = expand_expected_paths(binary_dir, skill.get("optional_output", []) or [], platform)
    return required, optional, required + optional


def all_expected_outputs_exist(expected_outputs):
    return bool(expected_outputs) and all(Path(path).is_file() for path in expected_outputs)


def should_skip_skill_for_existing_outputs(required_outputs, optional_outputs):
    return all_expected_outputs_exist(required_outputs or optional_outputs)


def get_binary_path(bin_dir, gamever, module_name, configured_path):
    return str(Path(bin_dir) / gamever / module_name / Path(configured_path).name)


def build_execution_plan(
    modules, *, platforms, bin_dir, gamever, vcall_finder_selector=None, include_post_process=False
) -> ExecutionPlan:
    if vcall_finder_selector is not None:
        raise ValueError("GoldSrc does not provide a generic vtable/vcall finder")
    if include_post_process:
        raise ValueError("GoldSrc analysis has no implicit Source2 post-process stage")
    return _build_execution_plan(modules, platforms=platforms, bin_dir=bin_dir, tag=gamever)


def topological_sort_skills(skills, platform=None):
    selected = platform or "windows"
    module = {
        "stage_index": 0,
        "name": "module",
        "path_windows": "game/module.dll",
        "path_linux": "game/module.so",
        "skills": list(skills),
        "symbols": [],
    }
    plan = _build_execution_plan([module], platforms=[selected], bin_dir=".analysis-plan", tag="contract-0")
    return [node.skill for node in plan.nodes]


def validate_module_skill_dependencies(modules):
    for platform in PLATFORMS:
        _build_execution_plan(modules, platforms=[platform], bin_dir=".analysis-plan", tag="contract-0")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _signature_values(payload: dict) -> list[str]:
    return [value for key, value in payload.items() if key.endswith("_sig") and isinstance(value, str)]


def reuse_unique_history_artifact(old_path: Path, output_path: Path, binary_path: Path) -> bool:
    if not old_path.is_file() or output_path.exists():
        return False
    try:
        payload = yaml.safe_load(old_path.read_bytes())
    except (OSError, yaml.YAMLError):
        return False
    if not isinstance(payload, dict):
        return False
    signatures = _signature_values(payload)
    if not signatures:
        return False
    binary = binary_path.read_bytes()
    matches = [signature_matches(binary, signature) for signature in signatures]
    if any(len(items) != 1 for items in matches):
        return False
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        yaml.safe_dump(payload, allow_unicode=True, sort_keys=False, width=120), encoding="utf-8", newline="\n"
    )
    return True


def _outputs(node, root: Path) -> tuple[list[Path], list[Path]]:
    module_root = root / node.module
    return (
        [module_root / name for name in node.required_outputs],
        [module_root / name for name in node.optional_outputs],
    )


def run_analysis_pipeline(
    node,
    *,
    binary_path: Path,
    game_root: Path,
    old_game_root: Path | None,
    agent: str,
    reporter,
    deterministic_runner=preprocess_skill,
    llm_runner=preprocess_skill_with_llm,
    agent_skill_runner=agent_runner.run_skill,
) -> str:
    required, optional = _outputs(node, game_root)
    skip_paths = [game_root / node.module / name for name in node.skip_if_exists]
    if (required and all(path.is_file() for path in required)) or (
        skip_paths and all(path.is_file() for path in skip_paths)
    ):
        return "existing"
    context = {
        "tag": game_root.name,
        "module": node.module,
        "platform": node.platform,
        "skill": node.skill,
        "binary_path": str(binary_path),
        "module_dir": str(game_root / node.module),
        "required_inputs": [str(game_root / node.module / name) for name in node.required_inputs],
        "optional_inputs": [str(game_root / node.module / name) for name in node.optional_inputs],
        "required_outputs": [str(path) for path in required],
        "optional_outputs": [str(path) for path in optional],
        "aliases": list(node.aliases),
    }
    if old_game_root is not None:
        for output in required:
            reuse_unique_history_artifact(
                old_game_root / node.module / output.name,
                output,
                binary_path,
            )
        if required and all(path.is_file() for path in required):
            return "history"
    reporter.emit(
        ProgressEvent.create(
            "stage_started",
            tag=game_root.name,
            module=node.module,
            platform=node.platform,
            skill=node.skill,
            stage="deterministic",
        )
    )
    deterministic_result = deterministic_runner(node.skill, context=context)
    if all(path.is_file() for path in required) if required else bool(deterministic_result):
        return "deterministic"
    reporter.emit(
        ProgressEvent.create(
            "stage_started",
            tag=game_root.name,
            module=node.module,
            platform=node.platform,
            skill=node.skill,
            stage="llm",
        )
    )
    llm_result = llm_runner(node.skill, context=context)
    if all(path.is_file() for path in required) if required else bool(llm_result):
        return "llm"
    reporter.emit(
        ProgressEvent.create(
            "stage_started",
            tag=game_root.name,
            module=node.module,
            platform=node.platform,
            skill=node.skill,
            stage="agent",
        )
    )
    succeeded = agent_skill_runner(
        node.skill,
        agent=agent,
        expected_yaml_paths=[str(path) for path in required],
        max_retries=node.max_retries,
    )
    if succeeded and (not required or all(path.is_file() for path in required)):
        return "agent"
    missing = [path.name for path in required if not path.is_file()]
    raise AnalysisRunError(f"Skill {node.id} did not produce required outputs: {', '.join(missing)}")


def analyze(
    *,
    gamever: str,
    config_path: str | Path,
    bindir: str | Path = "bin",
    platforms=PLATFORMS,
    oldgamever: str | None = None,
    modules_filter: set[str] | None = None,
    skill_filter: str | None = None,
    agent: str = "codex",
    reporter=None,
) -> ExecutionPlan:
    tag = validated_tag(gamever)
    if oldgamever is not None:
        validated_tag(oldgamever)
    _document, modules = load_config(config_path)
    if modules_filter is not None:
        modules = [module for module in modules if module["name"] in modules_filter]
    if skill_filter is not None:
        filtered = []
        for module in modules:
            selected = [skill for skill in module["skills"] if skill["name"] == skill_filter]
            if selected:
                filtered.append({**module, "skills": selected})
        if not filtered:
            raise AnalysisRunError(f"Skill not found: {skill_filter}")
        modules = filtered
    plan = _build_execution_plan(modules, platforms=platforms, bin_dir=bindir, tag=tag)
    reporter = reporter or NullReporter()
    root = Path(bindir) / tag
    old_root = Path(bindir) / oldgamever if oldgamever else None
    binary_identity: dict[tuple[str, str], tuple[Path, str]] = {}
    for module in modules:
        for platform in platforms:
            configured = module.get(f"path_{platform}")
            if configured is None:
                continue
            binary = Path(get_binary_path(bindir, tag, module["name"], configured))
            validate_binary(binary, platform)
            binary_identity[(module["name"], platform)] = (binary, _sha256(binary))
    reporter.emit(ProgressEvent.create("analysis_started", tag=tag, nodes=len(plan.nodes)))
    for node in plan.nodes:
        binary, before = binary_identity[(node.module, node.platform)]
        reporter.emit(
            ProgressEvent.create("skill_started", tag=tag, module=node.module, platform=node.platform, skill=node.skill)
        )
        stage = run_analysis_pipeline(
            node,
            binary_path=binary,
            game_root=root,
            old_game_root=old_root,
            agent=agent,
            reporter=reporter,
        )
        if _sha256(binary) != before:
            raise AnalysisRunError(f"Binary changed during analysis: {binary}")
        reporter.emit(
            ProgressEvent.create(
                "skill_completed", tag=tag, module=node.module, platform=node.platform, skill=node.skill, stage=stage
            )
        )
    for binary, before in binary_identity.values():
        if _sha256(binary) != before:
            raise AnalysisRunError(f"Binary changed during analysis: {binary}")
    reporter.emit(ProgressEvent.create("analysis_completed", tag=tag, nodes=len(plan.nodes)))
    return plan


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Analyze PE32/ELF32 GoldSrc binaries")
    parser.add_argument("-gamever", required=True)
    parser.add_argument("-oldgamever", default=None)
    parser.add_argument("-config", default=None)
    parser.add_argument("-bindir", default="bin")
    parser.add_argument("-platform", choices=["windows", "linux", "all-platform"], default="all-platform")
    parser.add_argument("-modules", default="*")
    parser.add_argument("-skill", default=None)
    parser.add_argument("-agent", default="codex")
    parser.add_argument("-console-events", action="store_true")
    parser.add_argument("-plan-only", action="store_true")
    return parser


def main(argv=None) -> int:
    args = _parser().parse_args(argv)
    try:
        config = resolve_analysis_config(args.gamever, args.config)
        platforms = PLATFORMS if args.platform == "all-platform" else (args.platform,)
        module_filter = (
            None if args.modules == "*" else {item.strip() for item in args.modules.split(",") if item.strip()}
        )
        if args.plan_only:
            _document, modules = load_config(config)
            plan = _build_execution_plan(modules, platforms=platforms, bin_dir=args.bindir, tag=args.gamever)
            print(yaml.safe_dump(plan.to_dict(), sort_keys=False))
        else:
            analyze(
                gamever=args.gamever,
                oldgamever=args.oldgamever,
                config_path=config,
                bindir=args.bindir,
                platforms=platforms,
                modules_filter=module_filter,
                skill_filter=args.skill,
                agent=args.agent,
                reporter=ConsoleReporter() if args.console_events else NullReporter(),
            )
    except (
        AnalysisConfigError,
        AnalysisPlanError,
        AnalysisRunError,
        BinaryFormatError,
        PreprocessorError,
        OSError,
        yaml.YAMLError,
    ) as exc:
        print(f"Error: {exc}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
