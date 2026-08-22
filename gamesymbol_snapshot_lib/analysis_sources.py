"""GoldSrc-specific analysis source, import, prompt, and reference ownership."""

from __future__ import annotations

import ast
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import PurePosixPath

from gamesymbol_snapshot_lib.model import SnapshotContract

PREPROCESSOR_ROOT = "ida_preprocessor_scripts"
REFERENCE_ROOT = f"{PREPROCESSOR_ROOT}/references"
PROMPT_ROOT = f"{PREPROCESSOR_ROOT}/prompt"
DEFAULT_REFERENCE_GAMEVER = "hl-10210"


class AnalysisSourceError(ValueError):
    pass


@dataclass(frozen=True)
class SourceIndex:
    owners_by_path: dict[str, frozenset[str]]
    analysis_paths: frozenset[str]

    def owners(self, path: str) -> frozenset[str]:
        return self.owners_by_path.get(path, frozenset())


def is_analysis_source_path(path: str) -> bool:
    return path.startswith(f"{PREPROCESSOR_ROOT}/")


def _decode(path: str, value: bytes | str) -> str:
    if isinstance(value, str):
        return value
    try:
        return value.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise AnalysisSourceError(f"Analysis source is not UTF-8: {path}") from exc


def _repo_module_path(module: str, source_path: str, tree: Mapping[str, bytes | str], level: int = 0) -> str | None:
    if level:
        parent = PurePosixPath(source_path).parent
        for _ in range(level - 1):
            parent = parent.parent
        candidate = parent / PurePosixPath(*module.split(".")) if module else parent
    elif module == "ida_analyze_util":
        candidate = PurePosixPath("ida_analyze_util.py")
    elif module.startswith("ida_preprocessor_scripts"):
        candidate = PurePosixPath(*module.split(".")).with_suffix(".py")
    elif "/" not in module and source_path.startswith(f"{PREPROCESSOR_ROOT}/"):
        candidate = PurePosixPath(source_path).parent / f"{module}.py"
    else:
        return None
    value = candidate.as_posix()
    return value if value in tree else None


def _source_metadata(path: str, tree: Mapping[str, bytes | str]) -> tuple[set[str], set[str], set[str]]:
    try:
        parsed = ast.parse(_decode(path, tree[path]), filename=path)
    except SyntaxError as exc:
        raise AnalysisSourceError(f"Unable to parse analysis source {path}: {exc}") from exc
    dependencies: set[str] = set()
    references: set[str] = set()
    prompts: set[str] = set()
    for node in ast.walk(parsed):
        if isinstance(node, ast.Import):
            for alias in node.names:
                dependency = _repo_module_path(alias.name, path, tree)
                if dependency:
                    dependencies.add(dependency)
        elif isinstance(node, ast.ImportFrom):
            dependency = _repo_module_path(node.module or "", path, tree, node.level)
            if dependency:
                dependencies.add(dependency)
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            value = node.value.replace("\\", "/")
            if value.endswith(".yaml") and (value.startswith("references/") or "/references/" in value):
                references.add(value[value.index("references/") :])
            if value.endswith(".md") and (value.startswith("prompt/") or "/prompt/" in value):
                prompts.add(value[value.index("prompt/") :])
    return dependencies, references, prompts


def _resolve_reference(
    template: str,
    *,
    contract: SnapshotContract,
    node,
    tree: Mapping[str, bytes | str],
    reference_gamever: str,
) -> str | None:
    relative = template.replace("{platform}", node.platform)
    relative = relative.replace("{module_name}", node.module_name).replace("{module}", node.module_name)
    candidates = []
    if "{gamever}" in relative:
        candidates.append(relative.replace("{gamever}", contract.game_version))
        candidates.append(relative.replace("{gamever}", reference_gamever))
    else:
        candidates.append(relative)
    for candidate in candidates:
        path = PurePosixPath(PREPROCESSOR_ROOT) / candidate
        if path.is_absolute() or ".." in path.parts or not path.as_posix().startswith(f"{REFERENCE_ROOT}/"):
            raise AnalysisSourceError(f"Reference template escapes the reference root: {template!r}")
        value = path.as_posix()
        if value in tree:
            return value
    return None


def build_source_index(
    contract: SnapshotContract,
    tree: Mapping[str, bytes | str],
    *,
    reference_gamever: str = DEFAULT_REFERENCE_GAMEVER,
    reject_orphan_references: bool = False,
) -> SourceIndex:
    owners: dict[str, set[str]] = {}
    metadata_cache: dict[str, tuple[set[str], set[str], set[str]]] = {}

    def add(path: str, node_id: str) -> None:
        owners.setdefault(path, set()).add(node_id)

    def visit(path: str, node_id: str, seen: set[str]) -> tuple[set[str], set[str]]:
        if path in seen or path not in tree:
            return set(), set()
        seen.add(path)
        add(path, node_id)
        dependencies, references, prompts = metadata_cache.setdefault(path, _source_metadata(path, tree))
        all_references = set(references)
        all_prompts = set(prompts)
        for dependency in dependencies:
            child_references, child_prompts = visit(dependency, node_id, seen)
            all_references.update(child_references)
            all_prompts.update(child_prompts)
        return all_references, all_prompts

    for node in contract.nodes.values():
        script = f"{PREPROCESSOR_ROOT}/{node.skill_name}.py"
        if script not in tree:
            continue
        references, prompts = visit(script, node.node_id, set())
        for template in references:
            resolved = _resolve_reference(
                template,
                contract=contract,
                node=node,
                tree=tree,
                reference_gamever=reference_gamever,
            )
            if resolved:
                add(resolved, node.node_id)
        if prompts:
            for path in tree:
                if path.startswith(f"{PROMPT_ROOT}/"):
                    add(path, node.node_id)

    reference_paths = {path for path in tree if path.startswith(f"{REFERENCE_ROOT}/") and path.endswith(".yaml")}
    orphaned = sorted(path for path in reference_paths if not owners.get(path))
    if reject_orphan_references and orphaned:
        raise AnalysisSourceError("Active reference YAML has no analysis consumer:\n" + "\n".join(orphaned))
    analysis_paths = frozenset(path for path in tree if is_analysis_source_path(path))
    return SourceIndex({path: frozenset(node_ids) for path, node_ids in owners.items()}, analysis_paths)


def validate_reference_consumers(tree: Mapping[str, bytes | str], indices: list[SourceIndex]) -> None:
    reference_paths = {path for path in tree if path.startswith(f"{REFERENCE_ROOT}/") and path.endswith(".yaml")}
    orphaned = sorted(path for path in reference_paths if not any(index.owners(path) for index in indices))
    if orphaned:
        raise AnalysisSourceError("Active reference YAML has no analysis consumer:\n" + "\n".join(orphaned))
