#!/usr/bin/env python3
"""Validate x86 binaries and execute the deterministic/LLM/agent analysis DAG."""

from __future__ import annotations

import argparse
import hashlib
import os
from dataclasses import dataclass
from pathlib import Path

import yaml
from dotenv import load_dotenv

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
from ida_llm_utils import validated_temperature
from ida_skill_preprocessor import PreprocessorError, preprocess_skill, preprocess_skill_with_llm
from process_reporter import ConsoleReporter, NullReporter, ProgressEvent

load_dotenv()

PLATFORMS = ("windows", "linux")
ANALYSIS_STAGES = ("history", "deterministic", "llm", "agent")
DEFAULT_BIN_DIR = "bin"
DEFAULT_PLATFORM = "windows,linux"
DEFAULT_MODULES = "*"
DEFAULT_AGENT = "claude"
DEFAULT_AGENT_MODEL = ""
DEFAULT_LLM_MODEL = "gpt-4o"
DEFAULT_DOWNLOAD_FILE = "download.yaml"
LLM_EFFORTS = frozenset({"none", "minimal", "low", "medium", "high", "xhigh"})


class AnalysisRunError(RuntimeError):
    pass


@dataclass
class AnalysisSummary:
    successful: int = 0
    failed: int = 0
    skipped: int = 0


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
    modules,
    *,
    platforms,
    bin_dir,
    gamever,
    default_max_retries=3,
    vcall_finder_selector=None,
    include_post_process=False,
) -> ExecutionPlan:
    if vcall_finder_selector is not None:
        raise ValueError("GoldSrc does not provide a generic vtable/vcall finder")
    if include_post_process:
        raise ValueError("GoldSrc analysis has no implicit Source2 post-process stage")
    return _build_execution_plan(
        modules,
        platforms=platforms,
        bin_dir=bin_dir,
        tag=gamever,
        default_max_retries=default_max_retries,
    )


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


def _split_gamever(gamever: str) -> tuple[str, int]:
    normalized = validated_tag(gamever)
    family, build = normalized.rsplit("-", 1)
    return family, int(build)


def resolve_oldgamever(gamever: str, bin_dir: str | Path) -> str | None:
    family, current_build = _split_gamever(gamever)
    root = Path(bin_dir)
    try:
        children = tuple(root.iterdir())
    except OSError:
        return None
    candidates: list[tuple[int, str]] = []
    for child in children:
        if not child.is_dir():
            continue
        try:
            candidate_family, candidate_build = _split_gamever(child.name)
        except (AnalysisConfigError, ValueError):
            continue
        if candidate_family == family and candidate_build < current_build:
            candidates.append((candidate_build, child.name))
    return max(candidates)[1] if candidates else None


def _is_major_update_gamever(gamever: str, download_path: str | Path = DEFAULT_DOWNLOAD_FILE) -> bool:
    path = Path(download_path)
    if not path.is_absolute():
        path = Path(__file__).resolve().parent / path
    try:
        document = yaml.safe_load(path.read_bytes()) or {}
    except (OSError, yaml.YAMLError):
        return False
    downloads = document.get("downloads")
    if not isinstance(downloads, list):
        return False
    for entry in downloads:
        if isinstance(entry, dict) and str(entry.get("tag", "")).strip() == gamever:
            return bool(entry.get("major_update", False))
    return False


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
    agent_model: str = DEFAULT_AGENT_MODEL,
    llm_config: dict | None = None,
    skip_preprocessors: bool = False,
    debug: bool = False,
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
        context["old_game_root"] = str(old_game_root)
        context["old_module_dir"] = str(old_game_root / node.module)
    if not skip_preprocessors:
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
        effective_llm_config = dict(llm_config or {})
        effective_llm_config["max_retries"] = node.max_retries
        llm_result = llm_runner(node.skill, context=context, llm_config=effective_llm_config)
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
        model=agent_model,
        debug=debug,
    )
    if succeeded and (not required or all(path.is_file() for path in required)):
        return "agent"
    missing = [path.name for path in required if not path.is_file()]
    raise AnalysisRunError(f"Skill {node.id} did not produce required outputs: {', '.join(missing)}")


def _select_execution_modules(modules, modules_filter=None, skill_filter=None):
    selected = list(modules)
    if modules_filter is not None:
        requested = list(modules_filter)
        available = {module["name"] for module in selected}
        missing = [name for name in requested if name not in available]
        if missing:
            raise AnalysisRunError(f"Module(s) not found: {', '.join(missing)}")
        selected = [module for module in selected if module["name"] in requested]
    if skill_filter is None:
        return selected
    available_skills = sorted({skill["name"] for module in selected for skill in module["skills"]})
    filtered = []
    for module in selected:
        skills = [skill for skill in module["skills"] if skill["name"] == skill_filter]
        if skills:
            filtered.append({**module, "skills": skills})
    if not filtered:
        available_label = ", ".join(available_skills) or "(none)"
        raise AnalysisRunError(f"Skill '{skill_filter}' not found; available skills: {available_label}")
    return filtered


def analyze(
    *,
    gamever: str,
    config_path: str | Path,
    bindir: str | Path = DEFAULT_BIN_DIR,
    platforms=PLATFORMS,
    oldgamever: str | None = None,
    modules_filter=None,
    skill_filter: str | None = None,
    agent: str = DEFAULT_AGENT,
    agent_model: str = DEFAULT_AGENT_MODEL,
    llm_config: dict | None = None,
    max_retries: int = 3,
    skip_error: bool = False,
    skip_preprocessors: bool = False,
    debug: bool = False,
    reporter=None,
    summary: AnalysisSummary | None = None,
) -> ExecutionPlan:
    tag = validated_tag(gamever)
    if oldgamever is not None:
        validated_tag(oldgamever)
        if _split_gamever(oldgamever)[0] != _split_gamever(tag)[0]:
            raise AnalysisRunError(f"Old game version must use the same game family as {tag}: {oldgamever}")
    _document, modules = load_config(config_path)
    modules = _select_execution_modules(modules, modules_filter, skill_filter)
    plan = _build_execution_plan(
        modules,
        platforms=platforms,
        bin_dir=bindir,
        tag=tag,
        default_max_retries=max_retries,
    )
    reporter = reporter or NullReporter()
    run_summary = summary if summary is not None else AnalysisSummary()
    root = Path(bindir) / tag
    old_root = Path(bindir) / oldgamever if oldgamever else None
    binary_identity: dict[tuple[str, str], tuple[Path, str]] = {}
    module_map = {module["name"]: module for module in modules}
    nodes_by_binary: dict[tuple[str, str], list] = {}
    for node in plan.nodes:
        nodes_by_binary.setdefault((node.module, node.platform), []).append(node)
    for (module_name, platform), binary_nodes in nodes_by_binary.items():
        configured = module_map[module_name].get(f"path_{platform}")
        binary = Path(get_binary_path(bindir, tag, module_name, configured))
        try:
            validate_binary(binary, platform)
            binary_identity[(module_name, platform)] = (binary, _sha256(binary))
        except (BinaryFormatError, OSError) as exc:
            run_summary.failed += len(binary_nodes)
            reporter.emit(
                ProgressEvent.create(
                    "binary_failed",
                    tag=tag,
                    module=module_name,
                    platform=platform,
                    error=str(exc),
                )
            )
            message = f"Binary validation failed for {module_name}:{platform}: {exc}"
            if not skip_error:
                raise AnalysisRunError(message) from exc
            print(f"Error: {message}; continuing (-skip_error)")
    reporter.emit(ProgressEvent.create("analysis_started", tag=tag, nodes=len(plan.nodes)))
    for node in plan.nodes:
        if (node.module, node.platform) not in binary_identity:
            continue
        binary, before = binary_identity[(node.module, node.platform)]
        reporter.emit(
            ProgressEvent.create("skill_started", tag=tag, module=node.module, platform=node.platform, skill=node.skill)
        )
        try:
            stage = run_analysis_pipeline(
                node,
                binary_path=binary,
                game_root=root,
                old_game_root=old_root,
                agent=agent,
                agent_model=agent_model,
                llm_config=llm_config,
                skip_preprocessors=skip_preprocessors,
                debug=debug,
                reporter=reporter,
            )
        except Exception as exc:
            run_summary.failed += 1
            reporter.emit(
                ProgressEvent.create(
                    "skill_failed",
                    tag=tag,
                    module=node.module,
                    platform=node.platform,
                    skill=node.skill,
                    error=str(exc),
                )
            )
            message = f"Skill {node.id} failed: {exc}"
            if not skip_error:
                raise AnalysisRunError(message) from exc
            print(f"Error: {message}; continuing (-skip_error)")
            continue
        if _sha256(binary) != before:
            raise AnalysisRunError(f"Binary changed during analysis: {binary}")
        if stage == "existing":
            run_summary.skipped += 1
        else:
            run_summary.successful += 1
        reporter.emit(
            ProgressEvent.create(
                "skill_completed", tag=tag, module=node.module, platform=node.platform, skill=node.skill, stage=stage
            )
        )
    for binary, before in binary_identity.values():
        if _sha256(binary) != before:
            raise AnalysisRunError(f"Binary changed during analysis: {binary}")
    reporter.emit(
        ProgressEvent.create(
            "analysis_completed",
            tag=tag,
            nodes=len(plan.nodes),
            successful=run_summary.successful,
            failed=run_summary.failed,
            skipped=run_summary.skipped,
        )
    )
    return plan


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Analyze PE32/ELF32 GoldSrc binaries", allow_abbrev=False)
    parser.add_argument(
        "-configyaml",
        default=None,
        help="Analysis config path; defaults to configs/<GAMEVER>.yaml",
    )
    parser.add_argument("-bindir", default=DEFAULT_BIN_DIR, help="Directory containing copied binaries")
    parser.add_argument(
        "-gamever",
        default=os.environ.get("GSVIBE_GAMEVER"),
        help="Game version tag (required, or set GSVIBE_GAMEVER)",
    )
    parser.add_argument(
        "-platform",
        default=DEFAULT_PLATFORM,
        help="Platforms to analyze, comma-separated (default: windows,linux)",
    )
    parser.add_argument(
        "-agent",
        default=os.environ.get("GSVIBE_AGENT", DEFAULT_AGENT),
        help="Agent executable (default: claude, or set GSVIBE_AGENT)",
    )
    parser.add_argument(
        "-agent_model",
        default=os.environ.get("GSVIBE_AGENT_MODEL", DEFAULT_AGENT_MODEL),
        help="Optional model for the selected Agent (or set GSVIBE_AGENT_MODEL)",
    )
    parser.add_argument(
        "-modules", default=DEFAULT_MODULES, help="Modules to analyze, comma-separated; '*' selects all"
    )
    parser.add_argument("-skill", default=None, help="Exact skill name to run")
    parser.add_argument(
        "-llm_model",
        default=os.environ.get("GSVIBE_LLM_MODEL", DEFAULT_LLM_MODEL),
        help="OpenAI-compatible model for LLM preprocessing (or set GSVIBE_LLM_MODEL)",
    )
    parser.add_argument(
        "-llm_apikey",
        default=os.environ.get("GSVIBE_LLM_APIKEY"),
        help="OpenAI-compatible API key (or set GSVIBE_LLM_APIKEY)",
    )
    parser.add_argument(
        "-llm_baseurl",
        default=os.environ.get("GSVIBE_LLM_BASEURL"),
        help="Optional OpenAI-compatible base URL (or set GSVIBE_LLM_BASEURL)",
    )
    parser.add_argument(
        "-llm_temperature",
        default=os.environ.get("GSVIBE_LLM_TEMPERATURE"),
        help="Optional LLM temperature from 0 through 2 (or set GSVIBE_LLM_TEMPERATURE)",
    )
    parser.add_argument(
        "-llm_fake_as",
        default=os.environ.get("GSVIBE_LLM_FAKE_AS"),
        help="Optional 'codex' compatibility override (or set GSVIBE_LLM_FAKE_AS)",
    )
    parser.add_argument(
        "-llm_effort",
        default=os.environ.get("GSVIBE_LLM_EFFORT"),
        help="LLM reasoning effort (default: medium, or set GSVIBE_LLM_EFFORT)",
    )
    parser.add_argument("-debug", action="store_true", help="Enable debug diagnostics and Agent output")
    parser.add_argument("-skip_error", action="store_true", help="Continue after runtime failures")
    parser.add_argument(
        "-skip_pp", action="store_true", help="Skip history and preprocessors; run Agent Skills directly"
    )
    parser.add_argument("-maxretry", type=int, default=3, help="Default total attempts per skill (1-20)")
    parser.add_argument(
        "-oldgamever",
        default=None,
        help="Old version for analysis context; auto-selects the latest older same-family version, or 'none'",
    )
    parser.add_argument("-console-events", action="store_true", help="Emit local JSONL progress events")
    return parser


def _parse_csv(parser, value, option, *, allowed=None):
    raw = str(value)
    parts = [part.strip() for part in raw.split(",")]
    if not parts or any(not part for part in parts):
        parser.error(f"{option} must be a comma-separated list of non-empty values")
    normalized = [part.casefold() for part in parts]
    if len(set(normalized)) != len(normalized):
        parser.error(f"{option} cannot contain duplicate values")
    if allowed is not None:
        invalid = [part for part in parts if part not in allowed]
        if invalid:
            parser.error(f"Invalid {option.lstrip('-')}: {', '.join(invalid)}. Must be one of: {', '.join(allowed)}")
    return parts


def _optional_text(value):
    if value is None:
        return None
    return str(value).strip() or None


def parse_args(argv=None):
    parser = _parser()
    args = parser.parse_args(argv)
    args.gamever = _optional_text(args.gamever)
    if args.gamever is None:
        parser.error("-gamever is required, or set GSVIBE_GAMEVER")
    try:
        validated_tag(args.gamever)
    except AnalysisConfigError as exc:
        parser.error(str(exc))

    args.platforms = _parse_csv(parser, args.platform, "-platform", allowed=PLATFORMS)
    args.modules = str(args.modules).strip()
    if args.modules == "*":
        args.module_filter = None
    else:
        args.module_filter = _parse_csv(parser, args.modules, "-modules")
        if "*" in args.module_filter:
            parser.error("-modules '*' must be used alone")

    if args.skill is not None:
        args.skill = str(args.skill).strip()
        if not args.skill:
            parser.error("-skill cannot be empty")

    args.agent = str(args.agent).strip()
    if not args.agent or agent_runner.detect_agent_kind(args.agent) is None:
        parser.error("-agent must identify a claude, codex, or opencode executable")
    args.agent_model = str(args.agent_model or "").strip()
    args.llm_model = str(args.llm_model).strip()
    if not args.llm_model:
        parser.error("-llm_model cannot be empty")
    args.llm_apikey = _optional_text(args.llm_apikey)
    args.llm_baseurl = _optional_text(args.llm_baseurl)
    try:
        args.llm_temperature = validated_temperature(args.llm_temperature)
    except ValueError as exc:
        parser.error(str(exc))
    args.llm_fake_as = _optional_text(args.llm_fake_as)
    if args.llm_fake_as is not None:
        args.llm_fake_as = args.llm_fake_as.casefold()
        if args.llm_fake_as != "codex":
            parser.error("-llm_fake_as must be 'codex' when set")
        if args.llm_baseurl is None:
            parser.error("-llm_baseurl is required when -llm_fake_as=codex")
    args.llm_effort = (_optional_text(args.llm_effort) or "medium").casefold()
    if args.llm_effort not in LLM_EFFORTS:
        parser.error(f"-llm_effort must be one of: {', '.join(sorted(LLM_EFFORTS))}")
    if not 1 <= args.maxretry <= 20:
        parser.error("-maxretry must be an integer from 1 to 20")

    if args.oldgamever is None:
        args.oldgamever = (
            None if _is_major_update_gamever(args.gamever) else resolve_oldgamever(args.gamever, args.bindir)
        )
    else:
        args.oldgamever = str(args.oldgamever).strip()
        if not args.oldgamever:
            parser.error("-oldgamever cannot be empty")
        if args.oldgamever.casefold() == "none":
            args.oldgamever = None
        else:
            try:
                old_family, _old_build = _split_gamever(args.oldgamever)
            except (AnalysisConfigError, ValueError) as exc:
                parser.error(str(exc))
            current_family, _current_build = _split_gamever(args.gamever)
            if old_family != current_family:
                parser.error("-oldgamever must use the same game family as -gamever")
    return args


def _llm_config_from_args(args) -> dict:
    return {
        "model": args.llm_model,
        "api_key": args.llm_apikey,
        "base_url": args.llm_baseurl,
        "temperature": args.llm_temperature,
        "effort": args.llm_effort,
        "fake_as": args.llm_fake_as,
        "max_retries": args.maxretry,
    }


def _print_main_configuration(args) -> None:
    print(f"Config file: {args.configyaml}")
    print(f"Binary directory: {args.bindir}")
    print(f"Game version: {args.gamever}")
    print(f"Old game version: {args.oldgamever or '(disabled)'}")
    print(f"Platforms: {', '.join(args.platforms)}")
    print(f"Modules filter: {args.modules}")
    if args.skill:
        print(f"Skill filter: {args.skill}")
    print(f"Agent: {args.agent}")
    if args.debug:
        print("Debug mode: enabled")
    if args.skip_error:
        print("Skip error mode: enabled")
    if args.skip_pp:
        print("Agent Skill only mode: enabled (-skip_pp)")


def _print_summary(summary: AnalysisSummary) -> None:
    print("\nSummary")
    print(f"  Successful: {summary.successful}")
    print(f"  Failed: {summary.failed}")
    print(f"  Skipped: {summary.skipped}")


def main(argv=None) -> int:
    args = parse_args(argv)
    summary = AnalysisSummary()
    try:
        args.configyaml = str(resolve_analysis_config(args.gamever, args.configyaml))
        _print_main_configuration(args)
        analyze(
            gamever=args.gamever,
            oldgamever=args.oldgamever,
            config_path=args.configyaml,
            bindir=args.bindir,
            platforms=args.platforms,
            modules_filter=args.module_filter,
            skill_filter=args.skill,
            agent=args.agent,
            agent_model=args.agent_model,
            llm_config=_llm_config_from_args(args),
            max_retries=args.maxretry,
            skip_error=args.skip_error,
            skip_preprocessors=args.skip_pp,
            debug=args.debug,
            reporter=ConsoleReporter() if args.console_events else NullReporter(),
            summary=summary,
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
        if summary.successful or summary.failed or summary.skipped:
            _print_summary(summary)
        return 1
    _print_summary(summary)
    return 1 if summary.failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
