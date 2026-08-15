"""Validated analysis configuration and immutable artifact DAG construction."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath

import yaml

from process_reporter import (
    EdgeType,
    ExecutionEdge,
    ExecutionJob,
    ExecutionNode,
    ExecutionPlan as ProcessExecutionPlan,
    ExecutionStage,
    PlanNodeType,
    build_job_id,
    build_stage_id,
    build_task_id,
)

PLATFORMS = ("windows", "linux")
SYMBOL_CATEGORIES = frozenset({"func", "gv", "vfunc", "vtable", "patch", "struct", "structmember"})
SAFE_NAME_RE = re.compile(r"^[A-Za-z0-9_.@$:+~-]+$", re.ASCII)


class AnalysisPlanError(ValueError):
    pass


@dataclass(frozen=True)
class PlanNode:
    id: str
    module: str
    skill: str
    platform: str
    required_inputs: tuple[str, ...]
    optional_inputs: tuple[str, ...]
    required_outputs: tuple[str, ...]
    optional_outputs: tuple[str, ...]
    prerequisites: tuple[str, ...]
    skip_if_exists: tuple[str, ...]
    max_retries: int
    aliases: tuple[str, ...]
    order: int


@dataclass(frozen=True)
class PlanEdge:
    source: str
    target: str
    kind: str
    artifact: str | None = None


@dataclass(frozen=True)
class ExecutionPlan:
    tag: str
    nodes: tuple[PlanNode, ...]
    edges: tuple[PlanEdge, ...]

    def to_dict(self) -> dict:
        return {
            "tag": self.tag,
            "nodes": [asdict(node) for node in self.nodes],
            "edges": [asdict(edge) for edge in self.edges],
        }


def module_declares_platform(module: dict, platform: str) -> bool:
    """Return True when a module declares any binary for the given platform.

    `path_<platform>` and `module_<platform>` are independent declarations; either
    one enables analysis for that platform.
    """
    return bool(module.get(f"path_{platform}") or module.get(f"module_{platform}"))


def _list_of_strings(value: object, field: str) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if not isinstance(value, list) or any(not isinstance(item, str) or not item for item in value):
        raise AnalysisPlanError(f"{field} must be a string or list of non-empty strings")
    return list(value)


def _safe_component(value: object, field: str) -> str:
    if not isinstance(value, str) or not value or value in {".", ".."} or not SAFE_NAME_RE.fullmatch(value):
        raise AnalysisPlanError(f"{field} must be one safe name component")
    return value


def validate_source_path(value: object, field: str) -> str:
    if not isinstance(value, str) or not value or "\\" in value or PureWindowsPath(value).is_absolute():
        raise AnalysisPlanError(f"{field} must be a relative POSIX path")
    path = PurePosixPath(value)
    if path.is_absolute() or "//" in value or any(part in {"", ".", ".."} for part in path.parts):
        raise AnalysisPlanError(f"{field} is unsafe: {value!r}")
    return path.as_posix()


def validate_artifact_path(value: object, field: str, platform: str | None = None) -> str:
    if not isinstance(value, str) or not value or "\\" in value:
        raise AnalysisPlanError(f"{field} must be a non-empty artifact filename")
    expanded = value.replace("{platform}", platform or "windows")
    path = PurePosixPath(expanded)
    if path.is_absolute() or len(path.parts) != 1 or path.name in {".", ".."}:
        raise AnalysisPlanError(f"{field} must stay in its module directory: {value!r}")
    if not expanded.endswith(".yaml"):
        raise AnalysisPlanError(f"{field} must end with .yaml: {value!r}")
    if platform is None:
        return value
    return expanded


def resolve_artifact_reference(
    module: str,
    value: object,
    field: str,
    *,
    platform: str,
    declared_modules: Iterable[str],
) -> str:
    """Resolve one CS2-style input path to a flat game-root artifact key."""

    if not isinstance(value, str) or not value or "\\" in value or PureWindowsPath(value).is_absolute():
        raise AnalysisPlanError(f"{field} must be a relative POSIX artifact path")
    expanded = value.replace("{platform}", platform)
    path = PurePosixPath(expanded)
    if path.is_absolute() or "//" in expanded or not expanded.endswith(".yaml"):
        raise AnalysisPlanError(f"{field} must resolve to a .yaml artifact inside the game-version root")

    parts: list[str] = [module]
    for part in path.parts:
        if part in {"", "."}:
            continue
        if part == "..":
            if not parts:
                raise AnalysisPlanError(f"{field} escapes the game-version root: {value!r}")
            parts.pop()
            continue
        parts.append(part)
    if len(parts) != 2 or parts[0] not in set(declared_modules):
        raise AnalysisPlanError(f"{field} must resolve to <module>/<artifact>.yaml: {value!r}")
    validate_artifact_path(parts[1], field, platform)
    return PurePosixPath(*parts).as_posix()


def _coalesced_list(mapping: dict, primary: str, aliases: tuple[str, ...], context: str) -> list[str]:
    values: list[str] = []
    for key in (primary, *aliases):
        values.extend(_list_of_strings(mapping.get(key), f"{context}.{key}"))
    return values


def _parse_skill(raw: object, context: str, *, module: str, declared_modules: Iterable[str]) -> dict:
    if not isinstance(raw, dict):
        raise AnalysisPlanError(f"{context} must be a mapping")
    name = _safe_component(raw.get("name"), f"{context}.name")
    platform = raw.get("platform")
    if platform is not None and platform not in PLATFORMS:
        raise AnalysisPlanError(f"{context}.platform must be windows or linux")
    retry = raw["max_retries"] if "max_retries" in raw else raw.get("retry")
    if retry is not None and (isinstance(retry, bool) or not isinstance(retry, int) or not 1 <= retry <= 20):
        raise AnalysisPlanError(f"{context}.max_retries must be an integer from 1 to 20")
    aliases = _coalesced_list(raw, "aliases", ("alias",), context)
    normalized = {
        "name": name,
        "description": raw.get("description"),
        "platform": platform,
        "expected_output": _coalesced_list(raw, "expected_output", ("required_output",), context),
        "expected_output_windows": _coalesced_list(
            raw, "expected_output_windows", ("required_output_windows",), context
        ),
        "expected_output_linux": _coalesced_list(raw, "expected_output_linux", ("required_output_linux",), context),
        "optional_output": _coalesced_list(raw, "optional_output", (), context),
        "optional_output_windows": _coalesced_list(raw, "optional_output_windows", (), context),
        "optional_output_linux": _coalesced_list(raw, "optional_output_linux", (), context),
        "expected_input": _coalesced_list(raw, "expected_input", ("required_input",), context),
        "expected_input_windows": _coalesced_list(raw, "expected_input_windows", ("required_input_windows",), context),
        "expected_input_linux": _coalesced_list(raw, "expected_input_linux", ("required_input_linux",), context),
        "optional_input": _coalesced_list(raw, "optional_input", (), context),
        "optional_input_windows": _coalesced_list(raw, "optional_input_windows", (), context),
        "optional_input_linux": _coalesced_list(raw, "optional_input_linux", (), context),
        "prerequisite": _coalesced_list(raw, "prerequisite", ("prerequisites",), context),
        "skip_if_exists": _coalesced_list(raw, "skip_if_exists", ("skip",), context),
        "max_retries": retry,
        "aliases": aliases,
    }
    for key in (
        "expected_output",
        "expected_output_windows",
        "expected_output_linux",
        "optional_output",
        "optional_output_windows",
        "optional_output_linux",
        "skip_if_exists",
    ):
        for index, value in enumerate(normalized[key]):
            validate_artifact_path(value, f"{context}.{key}[{index}]")
    for key in (
        "expected_input",
        "expected_input_windows",
        "expected_input_linux",
        "optional_input",
        "optional_input_windows",
        "optional_input_linux",
    ):
        platforms = ("windows",) if key.endswith("_windows") else ("linux",) if key.endswith("_linux") else PLATFORMS
        for index, value in enumerate(normalized[key]):
            for input_platform in platforms:
                resolve_artifact_reference(
                    module,
                    value,
                    f"{context}.{key}[{index}]",
                    platform=input_platform,
                    declared_modules=declared_modules,
                )
    return normalized


def _parse_symbol(raw: object, context: str) -> dict:
    if not isinstance(raw, dict):
        raise AnalysisPlanError(f"{context} must be a mapping")
    name = raw.get("name")
    if not isinstance(name, str) or not name.strip():
        raise AnalysisPlanError(f"{context}.name must be a non-empty string")
    if "type" in raw or "kind" in raw:
        raise AnalysisPlanError(f"{context} must use category; legacy type/kind fields are not accepted")
    category = raw.get("category")
    if category not in SYMBOL_CATEGORIES:
        raise AnalysisPlanError(f"{context}.category must be one of {', '.join(sorted(SYMBOL_CATEGORIES))}")
    platform = raw.get("platform")
    if platform is not None and platform not in PLATFORMS:
        raise AnalysisPlanError(f"{context}.platform must be windows or linux")
    artifact = raw.get("artifact")
    if artifact is not None:
        validate_artifact_path(artifact, f"{context}.artifact")
    result = dict(raw)
    result.update({"name": name.strip(), "category": category, "platform": platform})
    result["alias"] = _list_of_strings(raw.get("alias", raw.get("aliases")), f"{context}.alias")
    result["source_alias"] = _list_of_strings(raw.get("source_alias"), f"{context}.source_alias")
    if category == "structmember" and (
        not isinstance(raw.get("struct"), str) or not isinstance(raw.get("member"), str)
    ):
        raise AnalysisPlanError(f"{context} structmember requires struct and member metadata")
    if category == "struct" and result["source_alias"]:
        raise AnalysisPlanError(f"{context} struct metadata must not define source_alias")
    return result


def parse_config_document(document: object) -> list[dict]:
    if not isinstance(document, dict) or not isinstance(document.get("modules"), list):
        raise AnalysisPlanError("Analysis config must contain a modules list")
    modules = []
    module_spellings: dict[str, str] = {}
    declared_module_names: list[str] = []
    for module_index, raw in enumerate(document["modules"]):
        context = f"modules[{module_index}]"
        if not isinstance(raw, dict):
            raise AnalysisPlanError(f"{context} must be a mapping")
        name = _safe_component(raw.get("name"), f"{context}.name")
        prior = module_spellings.setdefault(name.casefold(), name)
        if prior != name or name in declared_module_names:
            raise AnalysisPlanError(f"Duplicate or case-insensitive module collision: {prior!r} and {name!r}")
        declared_module_names.append(name)
    module_spellings.clear()
    for module_index, raw in enumerate(document["modules"]):
        context = f"modules[{module_index}]"
        if not isinstance(raw, dict):
            raise AnalysisPlanError(f"{context} must be a mapping")
        name = _safe_component(raw.get("name"), f"{context}.name")
        prior = module_spellings.setdefault(name.casefold(), name)
        if prior != name:
            raise AnalysisPlanError(f"Case-insensitive module collision: {prior!r} and {name!r}")
        module = {"stage_index": module_index, "name": name, "description": raw.get("description")}
        for platform in PLATFORMS:
            value = raw.get(f"path_{platform}")
            binary_name = raw.get(f"module_{platform}")
            module[f"path_{platform}"] = (
                None if value is None else validate_source_path(value, f"{context}.path_{platform}")
            )
            if binary_name is not None:
                module[f"module_{platform}"] = _safe_component(binary_name, f"{context}.module_{platform}")
            elif module[f"path_{platform}"] is not None:
                # path_<platform> alone is enough to declare the platform; the
                # binary filename is derived from the last path component.
                module[f"module_{platform}"] = module[f"path_{platform}"].rsplit("/", 1)[-1]
            else:
                module[f"module_{platform}"] = None
        if not any(module[f"path_{platform}"] or module[f"module_{platform}"] for platform in PLATFORMS):
            raise AnalysisPlanError(f"{context} must declare at least one platform-specific binary")
        raw_skills = raw.get("skills") or []
        raw_symbols = raw.get("symbols") or []
        if not isinstance(raw_skills, list) or not isinstance(raw_symbols, list):
            raise AnalysisPlanError(f"{context}.skills and .symbols must be lists")
        module["skills"] = [
            _parse_skill(
                skill,
                f"{context}.skills[{index}]",
                module=name,
                declared_modules=declared_module_names,
            )
            for index, skill in enumerate(raw_skills)
        ]
        module["symbols"] = [
            _parse_symbol(symbol, f"{context}.symbols[{index}]") for index, symbol in enumerate(raw_symbols)
        ]
        skill_spellings: dict[str, str] = {}
        for skill in module["skills"]:
            previous = skill_spellings.setdefault(skill["name"].casefold(), skill["name"])
            if (
                previous != skill["name"]
                or previous == skill["name"]
                and sum(item["name"] == skill["name"] for item in module["skills"]) > 1
            ):
                raise AnalysisPlanError(f"Duplicate or case-colliding skill name in {name}: {skill['name']}")
        symbol_spellings: dict[str, str] = {}
        declared_structs = {item["name"] for item in module["symbols"] if item["category"] == "struct"}
        for symbol in module["symbols"]:
            prior_symbol = symbol_spellings.setdefault(symbol["name"].casefold(), symbol["name"])
            if prior_symbol != symbol["name"] or sum(item["name"] == symbol["name"] for item in module["symbols"]) > 1:
                raise AnalysisPlanError(f"Duplicate or case-colliding symbol name in {name}: {symbol['name']}")
            if symbol["category"] == "structmember" and symbol["struct"] not in declared_structs:
                raise AnalysisPlanError(f"{symbol['struct']!r} is not a declared struct in module {name!r}")
        modules.append(module)
    return modules


def load_config(path: str | Path) -> tuple[dict, list[dict]]:
    try:
        document = yaml.safe_load(Path(path).read_bytes()) or {}
    except (OSError, yaml.YAMLError) as exc:
        raise AnalysisPlanError(f"Unable to read analysis config {path}: {exc}") from exc
    return document, parse_config_document(document)


def _skill_paths(
    skill: dict,
    key: str,
    platform: str,
    *,
    module: str,
    declared_modules: Iterable[str],
) -> list[str]:
    values = list(skill.get(key, ()))
    values.extend(skill.get(f"{key}_{platform}", ()))
    if key in {"expected_input", "optional_input"}:
        return [
            resolve_artifact_reference(
                module,
                value,
                key,
                platform=platform,
                declared_modules=declared_modules,
            )
            for value in values
        ]
    return [f"{module}/{validate_artifact_path(value, key, platform)}" for value in values]


def symbol_artifact_filename(symbol: dict, platform: str) -> str:
    artifact = symbol.get("artifact")
    if artifact:
        return validate_artifact_path(artifact, "symbol.artifact", platform)
    stem = re.sub(r"[^A-Za-z0-9_.@+-]+", "_", symbol["name"]).strip("_")
    if not stem:
        raise AnalysisPlanError(f"Symbol name cannot form a safe artifact: {symbol['name']!r}")
    return f"{stem}.{platform}.yaml"


def _node_id(module: str, platform: str, skill: str) -> str:
    return f"{module}:{platform}:{skill}"


def _topological_order(nodes: list[PlanNode], edges: list[PlanEdge]) -> list[PlanNode]:
    by_id = {node.id: node for node in nodes}
    incoming = {node.id: set() for node in nodes}
    outgoing = {node.id: set() for node in nodes}
    for edge in edges:
        incoming[edge.target].add(edge.source)
        outgoing[edge.source].add(edge.target)
    ready = sorted((node.id for node in nodes if not incoming[node.id]), key=lambda item: by_id[item].order)
    ordered: list[PlanNode] = []
    while ready:
        current = ready.pop(0)
        ordered.append(by_id[current])
        for target in sorted(outgoing[current], key=lambda item: by_id[item].order):
            incoming[target].discard(current)
            if not incoming[target] and target not in {item.id for item in ordered} and target not in ready:
                ready.append(target)
        ready.sort(key=lambda item: by_id[item].order)
    if len(ordered) != len(nodes):
        blocked = sorted(node_id for node_id, dependencies in incoming.items() if dependencies)
        raise AnalysisPlanError(f"Analysis dependency cycle detected: {', '.join(blocked)}")
    return ordered


def build_execution_plan(
    modules: list[dict],
    *,
    platforms: Iterable[str],
    bin_dir: str | Path,
    tag: str,
    default_max_retries: int = 3,
    declared_modules: Iterable[str] | None = None,
) -> ExecutionPlan:
    selected = tuple(platforms)
    if not selected or any(platform not in PLATFORMS for platform in selected):
        raise AnalysisPlanError("Platforms must contain windows and/or linux")
    if (
        isinstance(default_max_retries, bool)
        or not isinstance(default_max_retries, int)
        or not 1 <= default_max_retries <= 20
    ):
        raise AnalysisPlanError("default_max_retries must be an integer from 1 to 20")
    root = Path(bin_dir) / tag
    declared_modules = tuple(declared_modules or (module["name"] for module in modules))
    nodes: list[PlanNode] = []
    producers: dict[tuple[str, str, str], str] = {}
    output_spellings: dict[tuple[str, str, str], str] = {}
    order = 0
    for module in modules:
        for platform in selected:
            if not module_declares_platform(module, platform):
                continue
            for skill in module["skills"]:
                if skill.get("platform") not in {None, platform}:
                    continue
                path_kwargs = {"module": module["name"], "declared_modules": declared_modules}
                required_outputs = tuple(_skill_paths(skill, "expected_output", platform, **path_kwargs))
                optional_outputs = tuple(_skill_paths(skill, "optional_output", platform, **path_kwargs))
                required_inputs = tuple(_skill_paths(skill, "expected_input", platform, **path_kwargs))
                optional_inputs = tuple(_skill_paths(skill, "optional_input", platform, **path_kwargs))
                skip_paths = tuple(
                    f"{module['name']}/{validate_artifact_path(path, 'skip_if_exists', platform)}"
                    for path in skill["skip_if_exists"]
                )
                node = PlanNode(
                    _node_id(module["name"], platform, skill["name"]),
                    module["name"],
                    skill["name"],
                    platform,
                    required_inputs,
                    optional_inputs,
                    required_outputs,
                    optional_outputs,
                    tuple(skill["prerequisite"]),
                    skip_paths,
                    skill["max_retries"] if skill["max_retries"] is not None else default_max_retries,
                    tuple(skill["aliases"]),
                    order,
                )
                order += 1
                nodes.append(node)
                for output in (*required_outputs, *optional_outputs):
                    key = (platform, output.casefold())
                    prior_spelling = output_spellings.setdefault(key, output)
                    if prior_spelling != output:
                        raise AnalysisPlanError(
                            f"Case-insensitive artifact collision: {prior_spelling!r} and {output!r}"
                        )
                    if key in producers:
                        raise AnalysisPlanError(f"Duplicate artifact producer for {module['name']}/{output}")
                    producers[key] = node.id
    edges: list[PlanEdge] = []
    for node in nodes:
        for artifact, required in (
            *((value, True) for value in node.required_inputs),
            *((value, False) for value in node.optional_inputs),
        ):
            producer = producers.get((node.platform, artifact.casefold()))
            if producer is not None:
                edges.append(PlanEdge(producer, node.id, "artifact" if required else "optional_input", artifact))
            elif required and not (root / Path(*PurePosixPath(artifact).parts)).is_file():
                raise AnalysisPlanError(f"Missing required artifact for {node.id}: {artifact}")
        module_skills = {
            candidate.skill: candidate.id
            for candidate in nodes
            if candidate.module == node.module and candidate.platform == node.platform
        }
        for prerequisite in node.prerequisites:
            if prerequisite not in module_skills:
                raise AnalysisPlanError(f"Missing prerequisite for {node.id}: {prerequisite}")
            edges.append(PlanEdge(module_skills[prerequisite], node.id, "prerequisite"))
    ordered = _topological_order(nodes, edges)
    return ExecutionPlan(tag, tuple(ordered), tuple(edges))


def build_process_execution_plan(
    plan: ExecutionPlan,
    modules: list[dict],
    *,
    platforms: Iterable[str],
    bin_dir: str | Path,
) -> ProcessExecutionPlan:
    """Project the validated GoldSrc DAG into the stable process-reporting schema."""

    selected_platforms = tuple(platforms)
    module_by_name = {module["name"]: module for module in modules}
    active_pairs = {(node.module, node.platform) for node in plan.nodes}
    active_modules = {module_name for module_name, _platform in active_pairs}
    stages: list[ExecutionStage] = []
    jobs: list[ExecutionJob] = []
    process_nodes: list[ExecutionNode] = []
    process_edges: list[ExecutionEdge] = []
    stage_by_module: dict[str, ExecutionStage] = {}
    job_by_pair: dict[tuple[str, str], ExecutionJob] = {}
    task_id_by_planner_node: dict[str, str] = {}

    for fallback_index, module in enumerate(modules):
        module_name = module["name"]
        if module_name not in active_modules:
            continue
        stage_index = module.get("stage_index", fallback_index)
        stage = ExecutionStage(
            id=build_stage_id(stage_index, module_name),
            stage_index=stage_index,
            module_name=module_name,
            description=module.get("description"),
        )
        stages.append(stage)
        stage_by_module[module_name] = stage
        for platform in selected_platforms:
            if (module_name, platform) not in active_pairs:
                continue
            binary_path = (
                str(Path(bin_dir) / plan.tag / module_name / module[f"module_{platform}"])
                if module.get(f"module_{platform}")
                else None
            )
            job = ExecutionJob(
                id=build_job_id(stage.id, platform),
                stage_id=stage.id,
                stage_index=stage.stage_index,
                module_name=module_name,
                platform=platform,
                binary_path=binary_path,
            )
            jobs.append(job)
            job_by_pair[(module_name, platform)] = job

    incoming: dict[str, list[str]] = {node.id: [] for node in plan.nodes}
    for edge in plan.edges:
        incoming.setdefault(edge.target, []).append(edge.source)
    layers: dict[str, int] = {}
    for node in plan.nodes:
        layers[node.id] = max((layers[source] + 1 for source in incoming.get(node.id, [])), default=0)

    job_orders: dict[str, int] = {}
    skill_by_module = {
        module["name"]: {skill["name"]: skill for skill in module.get("skills", [])} for module in modules
    }
    for node in plan.nodes:
        stage = stage_by_module[node.module]
        job = job_by_pair[(node.module, node.platform)]
        task_id = build_task_id(job.id, node.skill)
        task_id_by_planner_node[node.id] = task_id
        order = job_orders.get(job.id, 0)
        job_orders[job.id] = order + 1
        skill = skill_by_module.get(node.module, {}).get(node.skill, {})
        process_nodes.append(
            ExecutionNode(
                id=task_id,
                job_id=job.id,
                stage_id=stage.id,
                name=node.skill,
                node_type=PlanNodeType.SKILL,
                order=order,
                layer=layers[node.id],
                description=skill.get("description"),
                data={
                    "planner_node_id": node.id,
                    "required_inputs": list(node.required_inputs),
                    "optional_inputs": list(node.optional_inputs),
                    "required_outputs": list(node.required_outputs),
                    "optional_outputs": list(node.optional_outputs),
                    "prerequisites": list(node.prerequisites),
                    "skip_if_exists": list(node.skip_if_exists),
                    "max_retries": node.max_retries,
                    "aliases": list(node.aliases),
                },
            )
        )

    planner_nodes = {node.id: node for node in plan.nodes}
    for edge in plan.edges:
        source = planner_nodes[edge.source]
        target = planner_nodes[edge.target]
        edge_type = EdgeType(edge.kind)
        if edge_type == EdgeType.ARTIFACT and source.module != target.module:
            edge_type = EdgeType.CROSS_STAGE_ARTIFACT
        process_edges.append(
            ExecutionEdge(
                source=task_id_by_planner_node[edge.source],
                target=task_id_by_planner_node[edge.target],
                edge_type=edge_type,
                artifact=edge.artifact,
            )
        )

    process_edges.extend(
        ExecutionEdge(source=source.id, target=target.id, edge_type=EdgeType.STAGE_ORDER)
        for source, target in zip(stages, stages[1:])
    )
    process_edges.extend(
        ExecutionEdge(source=source.id, target=target.id, edge_type=EdgeType.STAGE_ORDER)
        for source, target in zip(jobs, jobs[1:])
    )
    for job in jobs:
        job_nodes = [node for node in process_nodes if node.job_id == job.id]
        process_edges.extend(
            ExecutionEdge(source=source.id, target=target.id, edge_type=EdgeType.STAGE_ORDER)
            for source, target in zip(job_nodes, job_nodes[1:])
        )

    return ProcessExecutionPlan(stages=stages, jobs=jobs, nodes=process_nodes, edges=process_edges)


def plan_sha256(plan: ExecutionPlan) -> str:
    data = json.dumps(plan.to_dict(), sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def expected_symbol_artifacts(modules: list[dict]) -> tuple[set[str], set[str]]:
    required: set[str] = set()
    optional: set[str] = set()
    spellings: dict[str, str] = {}
    symbol_owners: dict[str, str] = {}
    declared_modules = tuple(module["name"] for module in modules)
    for module in modules:
        for platform in PLATFORMS:
            if not module_declares_platform(module, platform):
                continue
            for skill in module["skills"]:
                if skill.get("platform") not in {None, platform}:
                    continue
                path_kwargs = {"module": module["name"], "declared_modules": declared_modules}
                required.update(_skill_paths(skill, "expected_output", platform, **path_kwargs))
                required.update(_skill_paths(skill, "expected_input", platform, **path_kwargs))
                optional.update(_skill_paths(skill, "optional_output", platform, **path_kwargs))
                optional.update(_skill_paths(skill, "optional_input", platform, **path_kwargs))
            for symbol in module["symbols"]:
                if symbol.get("platform") not in {None, platform}:
                    continue
                if symbol["category"] == "struct":
                    continue
                filename = symbol_artifact_filename(symbol, platform)
                symbol_path = f"{module['name']}/{filename}"
                prior_owner = symbol_owners.setdefault(symbol_path.casefold(), symbol["name"])
                if prior_owner != symbol["name"]:
                    raise AnalysisPlanError(
                        f"Symbols {prior_owner!r} and {symbol['name']!r} collide at {symbol_path!r}"
                    )
                required.add(symbol_path)
    optional.difference_update(required)
    for path in required | optional:
        prior = spellings.setdefault(path.casefold(), path)
        if prior != path:
            raise AnalysisPlanError(f"Case-insensitive artifact collision: {prior!r} and {path!r}")
    return required, optional
