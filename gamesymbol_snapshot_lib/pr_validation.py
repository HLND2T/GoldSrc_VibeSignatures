"""Pure impact planning for trusted incremental game-symbol PR validation."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from pathlib import PurePosixPath

from gamesymbol_snapshot_lib.analysis_sources import SourceIndex, is_analysis_source_path
from gamesymbol_snapshot_lib.impact_registry import ImpactRule
from gamesymbol_snapshot_lib.model import SnapshotContract

PLAN_SCHEMA_VERSION = 4
CACHE_MODE_WARM = "warm"
SNAPSHOT_DOMAIN_PATHS = frozenset(
    {
        "binary_hashing.py",
        "gamesymbol_candidate.py",
        "gamesymbol_metadata.py",
        "gamesymbol_snapshot.py",
        "gamesymbol_store.py",
    }
)


class ImpactPlanningError(ValueError):
    pass


@dataclass(frozen=True)
class PrValidationDecision:
    passed: bool
    errors: tuple[str, ...]


def evaluate_pr_validation(
    *,
    plan_result: str,
    validate_hosted_result: str,
    analyze_self_hosted_result: str,
    fork_analysis_blocked_result: str,
    has_actions: bool,
    has_analysis: bool,
    has_hosted: bool,
    same_repository: bool,
) -> PrValidationDecision:
    results = {
        "plan": plan_result,
        "validate-hosted": validate_hosted_result,
        "analyze-self-hosted": analyze_self_hosted_result,
        "fork-analysis-blocked": fork_analysis_blocked_result,
    }
    allowed_results = {"success", "failure", "cancelled", "skipped"}
    errors = [
        f"{job} reported unsupported result {result!r}"
        for job, result in results.items()
        if result not in allowed_results
    ]
    if plan_result != "success":
        errors.append(f"plan must succeed, got {plan_result}")
        return PrValidationDecision(False, tuple(errors))
    if (has_analysis or has_hosted) and not has_actions:
        errors.append("planner action outputs are inconsistent")

    expected = {
        "validate-hosted": "success" if has_hosted else "skipped",
        "analyze-self-hosted": "success" if has_analysis and same_repository else "skipped",
        "fork-analysis-blocked": "failure" if has_analysis and not same_repository else "skipped",
    }
    for job, expected_result in expected.items():
        if results[job] != expected_result:
            errors.append(f"{job} must be {expected_result}, got {results[job]}")
    if has_analysis and not same_repository:
        errors.append("analysis nodes from a fork cannot use the trusted self-hosted runner")
    return PrValidationDecision(not errors, tuple(errors))


@dataclass(frozen=True)
class ChangedPath:
    status: str
    old_path: str | None
    new_path: str | None

    def __post_init__(self) -> None:
        if self.status not in {"A", "M", "D", "R", "C"}:
            raise ImpactPlanningError(f"Unsupported changed-path status: {self.status!r}")
        for value in (self.old_path, self.new_path):
            if value is not None and (
                "\\" in value or PurePosixPath(value).is_absolute() or ".." in PurePosixPath(value).parts
            ):
                raise ImpactPlanningError(f"Unsafe changed path: {value!r}")
        if self.status == "A" and (self.old_path is not None or self.new_path is None):
            raise ImpactPlanningError("Added path must define only new_path")
        if self.status == "D" and (self.old_path is None or self.new_path is not None):
            raise ImpactPlanningError("Deleted path must define only old_path")
        if self.status == "M" and (self.old_path is None or self.new_path != self.old_path):
            raise ImpactPlanningError("Modified path must use the same old_path and new_path")
        if self.status in {"R", "C"} and (self.old_path is None or self.new_path is None):
            raise ImpactPlanningError("Rename/copy path must define old_path and new_path")

    @property
    def paths(self) -> tuple[str, ...]:
        return tuple(dict.fromkeys(path for path in (self.old_path, self.new_path) if path is not None))


@dataclass(frozen=True)
class TagImpact:
    tag: str
    analysis_nodes: tuple[str, ...]
    invalidated_paths: tuple[str, ...]
    snapshot_rebuild: bool
    gamedata_rebuild: bool
    reasons: tuple[str, ...]

    @property
    def has_actions(self) -> bool:
        return bool(self.analysis_nodes or self.snapshot_rebuild or self.gamedata_rebuild)


@dataclass(frozen=True)
class BoundImpactPlan:
    base_sha: str
    head_sha: str
    merge_sha: str
    base_bin_commit: str | None
    merge_bin_commit: str | None
    tags: tuple[TagImpact, ...]
    digests: dict[str, str | None]

    def document(self) -> dict:
        payload = {
            "schema_version": PLAN_SCHEMA_VERSION,
            "base_sha": self.base_sha,
            "head_sha": self.head_sha,
            "merge_sha": self.merge_sha,
            "base_bin_commit": self.base_bin_commit,
            "merge_bin_commit": self.merge_bin_commit,
            "cache_mode": CACHE_MODE_WARM,
            "tags": [asdict(tag) for tag in self.tags],
            "digests": dict(sorted(self.digests.items())),
        }
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        payload["plan_sha256"] = hashlib.sha256(encoded).hexdigest()
        return payload

    def canonical_bytes(self) -> bytes:
        return (json.dumps(self.document(), sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def _registry_nodes(
    rules: tuple[ImpactRule, ...], paths: set[str], contract: SnapshotContract
) -> tuple[set[str], list[str]]:
    selected: set[str] = set()
    reasons = []
    for rule in rules:
        if rule.tags is not None and contract.game_version not in rule.tags:
            continue
        matched = sorted(path for path in paths if rule.matches_path(path))
        if not matched:
            continue
        for node in contract.nodes.values():
            if rule.scope == "all":
                selected.add(node.node_id)
            elif rule.scope == "platform" and node.platform in rule.platforms:
                selected.add(node.node_id)
            elif rule.scope == "category" and node.categories & rule.categories:
                selected.add(node.node_id)
            elif rule.scope == "skill" and node.skill_name in rule.skills:
                selected.add(node.node_id)
        reasons.append(f"registry: {rule.reason} ({', '.join(matched)})")
    return selected, reasons


def _skill_path_nodes(paths: set[str], contract: SnapshotContract) -> set[str]:
    skills = {
        parts[2]
        for path in paths
        if (parts := PurePosixPath(path).parts)[:2] == (".claude", "skills") and len(parts) >= 4
    }
    return {node.node_id for node in contract.nodes.values() if node.skill_name in skills}


def _downstream_closure(contract: SnapshotContract, seeds: set[str]) -> set[str]:
    selected = set(seeds)
    outgoing: dict[str, set[str]] = {}
    for edge in contract.analysis_plan.edges:
        outgoing.setdefault(edge.source, set()).add(edge.target)
    pending = list(seeds)
    while pending:
        current = pending.pop()
        for target in outgoing.get(current, ()):
            if target not in selected:
                selected.add(target)
                pending.append(target)
    return selected


def _artifact_owner_seeds(
    *,
    tag: str,
    changed_paths: tuple[ChangedPath, ...],
    base_contract: SnapshotContract | None,
    merge_contract: SnapshotContract,
) -> tuple[set[str], list[str]]:
    prefix = f"bin_artifacts/{tag}/"
    seeds: set[str] = set()
    reasons: list[str] = []
    for change in changed_paths:
        candidates = []
        if change.old_path is not None and change.old_path.startswith(prefix):
            candidates.append((change.old_path, base_contract, True))
        if change.new_path is not None and change.new_path.startswith(prefix):
            candidates.append((change.new_path, merge_contract, False))
        for path, contract, old_path in candidates:
            relative = path.removeprefix(prefix)
            if contract is None or relative not in contract.formal_paths:
                raise ImpactPlanningError(f"Changed artifact is outside the formal contract for {tag}: {path}")
            if old_path and relative not in merge_contract.formal_paths:
                raise ImpactPlanningError(
                    f"Deleted or renamed artifact is no longer declared by the merge contract for {tag}: {path}"
                )
            owners = set(contract.owners_by_path[relative])
            missing_owners = owners - set(merge_contract.nodes)
            if missing_owners:
                raise ImpactPlanningError(f"Artifact owner was removed from the merge contract for {tag}: {path}")
            seeds.update(owners)
            reasons.append(f"analysis artifact changed: {path}")
    return seeds, reasons


def _snapshot_domain_changed(paths: set[str]) -> bool:
    return any(
        path in SNAPSHOT_DOMAIN_PATHS
        or path.startswith("gamesymbol_snapshot_lib/")
        and path.rsplit("/", 1)[-1]
        not in {"analysis_sources.py", "impact_registry.py", "pr_cli.py", "pr_validation.py"}
        for path in paths
    )


def _gamedata_domain_changed(paths: set[str]) -> bool:
    return any(
        path.startswith("gamedata_") or path == "update_gamedata.py" or path.startswith("gamedata-generators/")
        for path in paths
    )


def plan_tag_impact(
    *,
    tag: str,
    base_contract: SnapshotContract | None,
    merge_contract: SnapshotContract | None,
    changed_paths: tuple[ChangedPath, ...],
    base_sources: SourceIndex | None,
    merge_sources: SourceIndex | None,
    base_rules: tuple[ImpactRule, ...],
    merge_rules: tuple[ImpactRule, ...],
    binary_changed_pairs: frozenset[tuple[str, str]] = frozenset(),
    fail_unmapped_analysis: bool = True,
) -> TagImpact:
    artifact_prefix = f"bin_artifacts/{tag}/"
    has_artifact_changes = any(path.startswith(artifact_prefix) for change in changed_paths for path in change.paths)
    if merge_contract is None:
        if has_artifact_changes:
            raise ImpactPlanningError(f"Changed artifacts have no merge contract for {tag}")
        return TagImpact(tag, (), (), False, False, ())
    if not merge_contract.formal_paths:
        if has_artifact_changes:
            raise ImpactPlanningError(f"Changed artifacts have an empty merge contract for {tag}")
        return TagImpact(tag, (), (), False, False, ())

    all_paths = {path for change in changed_paths for path in change.paths}
    seeds: set[str] = set()
    reasons: list[str] = []
    artifact_seeds, artifact_reasons = _artifact_owner_seeds(
        tag=tag,
        changed_paths=changed_paths,
        base_contract=base_contract,
        merge_contract=merge_contract,
    )
    seeds.update(artifact_seeds)
    reasons.extend(artifact_reasons)
    for path in sorted(all_paths):
        owners = set()
        if base_sources:
            owners.update(base_sources.owners(path))
        if merge_sources:
            owners.update(merge_sources.owners(path))
        owners.intersection_update(merge_contract.nodes)
        if owners:
            seeds.update(owners)
            reasons.append(f"analysis source: {path}")
        elif fail_unmapped_analysis and is_analysis_source_path(path):
            raise ImpactPlanningError(f"Changed analysis source has no mapped consumer for {tag}: {path}")

    skill_nodes = _skill_path_nodes(all_paths, merge_contract)
    if skill_nodes:
        seeds.update(skill_nodes)
        reasons.append("analysis Agent skill changed")

    registry_nodes, registry_reasons = _registry_nodes(base_rules + merge_rules, all_paths, merge_contract)
    seeds.update(registry_nodes)
    reasons.extend(registry_reasons)

    config_changed = base_contract is None or base_contract.config_sha256 != merge_contract.config_sha256
    if base_contract is not None:
        for node_id, node in merge_contract.nodes.items():
            prior = base_contract.nodes.get(node_id)
            if prior is None or prior.fingerprint != node.fingerprint:
                seeds.add(node_id)
                reasons.append(f"config node changed: {node_id}")
    elif merge_contract.nodes:
        seeds.update(merge_contract.nodes)
        reasons.append("new tag contract")

    for module, platform in binary_changed_pairs:
        pair_nodes = {
            node.node_id
            for node in merge_contract.nodes.values()
            if node.module_name == module and node.platform == platform
        }
        seeds.update(pair_nodes)
        if pair_nodes:
            reasons.append(f"binary changed: {module}/{platform}")

    snapshot_rebuild = bool(seeds or config_changed or _snapshot_domain_changed(all_paths))
    gamedata_rebuild = bool(seeds or config_changed or _gamedata_domain_changed(all_paths))

    if not seeds and not snapshot_rebuild and not gamedata_rebuild:
        return TagImpact(tag, (), (), False, False, ())

    selected = _downstream_closure(merge_contract, seeds)
    invalidated = sorted(path for node_id in selected for path in merge_contract.nodes[node_id].outputs)
    ordered_nodes = tuple(node.id for node in merge_contract.analysis_plan.nodes if node.id in selected)
    return TagImpact(
        tag=tag,
        analysis_nodes=ordered_nodes,
        invalidated_paths=tuple(dict.fromkeys(invalidated)),
        snapshot_rebuild=snapshot_rebuild,
        gamedata_rebuild=gamedata_rebuild,
        reasons=tuple(dict.fromkeys(reasons)),
    )
