"""Git-facing orchestration for trusted base PR impact planning and materialization."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import tempfile
from pathlib import Path

import yaml

from analysis_config import validated_tag
from bin_artifact_contract import BinArtifactContractError, build_game_artifact_inventory
from gamesymbol_snapshot_lib.analysis_sources import (
    build_source_index,
    is_analysis_source_path,
    validate_reference_consumers,
)
from gamesymbol_snapshot_lib.config import load_contract
from gamesymbol_snapshot_lib.impact_registry import parse_impact_registry
from gamesymbol_snapshot_lib.operations import _atomic_write
from gamesymbol_snapshot_lib.paths import (
    ensure_real_tree,
    is_reparse_point,
    iter_yaml_paths,
    path_from_key,
)
from gamesymbol_snapshot_lib.pr_validation import (
    BoundImpactPlan,
    CACHE_MODE_WARM,
    ChangedPath,
    ImpactPlanningError,
    TagImpact,
    plan_tag_impact,
)


class PrCliError(ValueError):
    pass


class GitRepository:
    def __init__(self, path: str | Path):
        self.path = Path(path).resolve()

    def _run(self, *args: str, check: bool = True) -> bytes:
        result = subprocess.run(
            ["git", "-C", str(self.path), *args],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if check and result.returncode != 0:
            message = result.stderr.decode("utf-8", errors="replace").strip()
            raise PrCliError(f"git {' '.join(args)} failed: {message}")
        return result.stdout

    def resolve(self, ref: str) -> str:
        return self._run("rev-parse", "--verify", f"{ref}^{{commit}}").decode().strip()

    def read(self, ref: str, path: str) -> bytes | None:
        probe = subprocess.run(
            ["git", "-C", str(self.path), "cat-file", "-e", f"{ref}:{path}"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        if probe.returncode != 0:
            return None
        return self._run("show", f"{ref}:{path}")

    def list_files(self, ref: str) -> tuple[str, ...]:
        raw = self._run("ls-tree", "-r", "--name-only", "-z", ref)
        return tuple(item.decode("utf-8") for item in raw.split(b"\0") if item)

    def gitlink(self, ref: str, path: str) -> str | None:
        raw = self._run("ls-tree", ref, "--", path).decode("utf-8", errors="replace").strip()
        if not raw:
            return None
        metadata, _separator, listed_path = raw.partition("\t")
        parts = metadata.split()
        if listed_path != path or len(parts) != 3 or parts[0] != "160000" or parts[1] != "commit":
            raise PrCliError(f"{path} is not a gitlink at {ref}")
        return parts[2]

    def changed_paths(self, base: str, merge: str) -> tuple[ChangedPath, ...]:
        raw = self._run("diff", "--name-status", "-z", "-M", "-C", base, merge)
        fields = [field.decode("utf-8") for field in raw.split(b"\0") if field]
        changes = []
        index = 0
        while index < len(fields):
            status_field = fields[index]
            index += 1
            status = status_field[0]
            if status in {"R", "C"}:
                if index + 1 >= len(fields):
                    raise PrCliError("Truncated git rename/copy diff")
                changes.append(ChangedPath(status, fields[index], fields[index + 1]))
                index += 2
            elif status == "A":
                changes.append(ChangedPath(status, None, fields[index]))
                index += 1
            elif status == "D":
                changes.append(ChangedPath(status, fields[index], None))
                index += 1
            elif status == "M":
                changes.append(ChangedPath(status, fields[index], fields[index]))
                index += 1
            else:
                raise PrCliError(f"Unsupported git diff status: {status_field}")
        return tuple(changes)


def _sha256(value: bytes | None) -> str | None:
    return None if value is None else hashlib.sha256(value).hexdigest()


def _artifact_inventory(
    repo: GitRepository,
    ref: str,
    tag: str,
    contract,
    *,
    require_complete: bool,
) -> tuple[tuple[dict, ...], str | None]:
    prefix = f"bin_artifacts/{validated_tag(tag)}/"
    paths = tuple(path for path in repo.list_files(ref) if path.startswith(prefix))
    if contract is None:
        if paths:
            raise ImpactPlanningError(f"Artifact tree has no configured tag at {ref}: {prefix}")
        return (), None
    relative_paths = {path.removeprefix(prefix) for path in paths}
    extra = relative_paths - contract.formal_paths
    missing = contract.required_paths - relative_paths
    if extra or require_complete and missing:
        raise ImpactPlanningError(
            f"Artifact inventory mismatch for {tag} at {ref}: missing={sorted(missing)!r}; extra={sorted(extra)!r}"
        )
    selected = (
        contract.required_paths | (contract.optional_paths & relative_paths) if require_complete else relative_paths
    )
    entries = []
    for relative in sorted(selected):
        raw = repo.read(ref, f"{prefix}{relative}")
        if raw is None:
            raise ImpactPlanningError(f"Artifact disappeared while reading {tag} at {ref}: {relative}")
        entries.append({"path": relative, "size": len(raw), "sha256": _sha256(raw)})
    if not entries:
        return (), None
    encoded = json.dumps(entries, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return tuple(entries), hashlib.sha256(encoded).hexdigest()


def _tags(repo: GitRepository, ref: str) -> tuple[str, ...]:
    raw = repo.read(ref, "configs/config.yaml")
    if raw is None:
        return ()
    document = yaml.safe_load(raw)
    if not isinstance(document, dict) or not isinstance(document.get("gamevers"), list):
        raise PrCliError(f"configs/config.yaml is invalid at {ref}")
    tags = tuple(validated_tag(value) for value in document["gamevers"])
    if len(tags) != len(set(tags)):
        raise PrCliError(f"configs/config.yaml contains duplicate tags at {ref}")
    return tags


def _contract(repo: GitRepository, ref: str, tag: str, temporary: Path):
    raw = repo.read(ref, f"configs/{tag}.yaml")
    if raw is None:
        return None, None
    path = temporary / ref.replace("/", "_") / "configs" / f"{tag}.yaml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    checkout_root = temporary / ref.replace("/", "_")
    return load_contract(
        path,
        tag,
        checkout_root / "bin",
        artifactdir=checkout_root / "bin_artifacts",
    ), raw


def _tree(repo: GitRepository, ref: str) -> dict[str, bytes]:
    paths = [
        path
        for path in repo.list_files(ref)
        if path == "ida_analyze_util.py" or path.startswith("ida_preprocessor_scripts/")
    ]
    return {path: value for path in paths if (value := repo.read(ref, path)) is not None}


def _registry(repo: GitRepository, ref: str):
    raw = repo.read(ref, "gamesymbol-impact.yaml")
    if raw is None:
        return (), None
    return parse_impact_registry(yaml.safe_load(raw)), raw


def _binary_changes(
    *,
    tag: str,
    base_contract,
    merge_contract,
    bin_repo: GitRepository | None,
    base_commit: str | None,
    merge_commit: str | None,
) -> frozenset[tuple[str, str]]:
    if bin_repo is None or base_commit is None or merge_commit is None or base_commit == merge_commit:
        return frozenset()
    changed = {path for change in bin_repo.changed_paths(base_commit, merge_commit) for path in change.paths}
    pairs = set()
    for contract in (base_contract, merge_contract):
        if contract is None:
            continue
        for pair, target in contract.binary_targets.items():
            if f"{tag}/{target.module_name}/{target.binary_name}" in changed:
                pairs.add(pair)
    return frozenset(pairs)


def build_plan(
    *,
    repo_root: str | Path,
    base_ref: str,
    head_ref: str,
    merge_ref: str,
    bin_repo_root: str | Path | None = None,
) -> BoundImpactPlan:
    repo = GitRepository(repo_root)
    base_sha, head_sha, merge_sha = (repo.resolve(ref) for ref in (base_ref, head_ref, merge_ref))
    base_bin = repo.gitlink(base_sha, "bin")
    merge_bin = repo.gitlink(merge_sha, "bin")
    bin_repo = GitRepository(bin_repo_root) if bin_repo_root is not None else None
    changes = repo.changed_paths(base_sha, merge_sha)
    base_rules, base_registry_raw = _registry(repo, base_sha)
    merge_rules, merge_registry_raw = _registry(repo, merge_sha)
    base_tree, merge_tree = _tree(repo, base_sha), _tree(repo, merge_sha)
    base_tags, merge_tags = _tags(repo, base_sha), _tags(repo, merge_sha)
    ordered_tags = tuple(dict.fromkeys((*merge_tags, *(tag for tag in base_tags if tag not in merge_tags))))
    known_tags = set(ordered_tags)
    for change in changes:
        for path in change.paths:
            parts = path.split("/")
            if parts[0] == "bin_artifacts":
                if len(parts) != 4:
                    raise ImpactPlanningError(f"Invalid tracked artifact path: {path}")
                try:
                    artifact_tag = validated_tag(parts[1])
                except ValueError as exc:
                    raise ImpactPlanningError(f"Invalid tracked artifact path: {path}") from exc
                if artifact_tag not in known_tags:
                    raise ImpactPlanningError(f"Tracked artifact has no configured tag: {path}")
    impacts: list[TagImpact] = []
    digests: dict[str, str | None] = {
        "base_config_index": _sha256(repo.read(base_sha, "configs/config.yaml")),
        "merge_config_index": _sha256(repo.read(merge_sha, "configs/config.yaml")),
        "base_registry": _sha256(base_registry_raw),
        "merge_registry": _sha256(merge_registry_raw),
    }
    with tempfile.TemporaryDirectory(prefix="gamesymbol-pr-plan-") as temporary_name:
        temporary = Path(temporary_name)
        base_contracts = {}
        merge_contracts = {}
        base_sources = {}
        merge_sources = {}
        artifact_inventories = {}
        for tag in ordered_tags:
            base_contracts[tag], base_config_raw = _contract(repo, base_sha, tag, temporary)
            merge_contracts[tag], merge_config_raw = _contract(repo, merge_sha, tag, temporary)
            digests[f"base_config:{tag}"] = _sha256(base_config_raw)
            digests[f"merge_config:{tag}"] = _sha256(merge_config_raw)
            if base_contracts[tag] is not None:
                base_sources[tag] = build_source_index(base_contracts[tag], base_tree)
            if merge_contracts[tag] is not None:
                merge_sources[tag] = build_source_index(merge_contracts[tag], merge_tree)
            base_artifacts, base_artifact_digest = _artifact_inventory(
                repo,
                base_sha,
                tag,
                base_contracts[tag],
                require_complete=False,
            )
            merge_artifacts, merge_artifact_digest = _artifact_inventory(
                repo,
                merge_sha,
                tag,
                merge_contracts[tag],
                require_complete=True,
            )
            digests[f"base_artifacts:{tag}"] = base_artifact_digest
            digests[f"merge_artifacts:{tag}"] = merge_artifact_digest
            artifact_inventories[tag] = (base_artifacts, merge_artifacts)

        validate_reference_consumers(merge_tree, list(merge_sources.values()))
        for path in sorted({path for change in changes for path in change.paths if is_analysis_source_path(path)}):
            if not any(index.owners(path) for index in (*base_sources.values(), *merge_sources.values())):
                raise ImpactPlanningError(f"Changed analysis source has no mapped consumer: {path}")
        for tag in ordered_tags:
            impact = plan_tag_impact(
                tag=tag,
                base_contract=base_contracts[tag],
                merge_contract=merge_contracts[tag],
                changed_paths=changes,
                base_sources=base_sources.get(tag),
                merge_sources=merge_sources.get(tag),
                base_rules=base_rules,
                merge_rules=merge_rules,
                metadata_changed=False,
                gamedata_changed=False,
                binary_changed_pairs=_binary_changes(
                    tag=tag,
                    base_contract=base_contracts[tag],
                    merge_contract=merge_contracts[tag],
                    bin_repo=bin_repo,
                    base_commit=base_bin,
                    merge_commit=merge_bin,
                ),
                base_snapshot_trusted=True,
                fail_unmapped_analysis=False,
            )
            if impact.has_actions:
                impacts.append(impact)
    return BoundImpactPlan(base_sha, head_sha, merge_sha, base_bin, merge_bin, tuple(impacts), digests)


def load_bound_plan(path: str | Path) -> dict:
    document = json.loads(Path(path).read_text(encoding="utf-8"))
    if (
        not isinstance(document, dict)
        or document.get("schema_version") != 3
        or document.get("cache_mode") != CACHE_MODE_WARM
    ):
        raise PrCliError("Invalid bound impact plan")
    digest = document.pop("plan_sha256", None)
    encoded = json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if digest != hashlib.sha256(encoded).hexdigest():
        raise PrCliError("Impact plan digest mismatch")
    document["plan_sha256"] = digest
    return document


def verify_bound_plan_checkout(
    *, repo_root: str | Path, plan_path: str | Path, merge_ref: str
) -> tuple[GitRepository, dict]:
    repo = GitRepository(repo_root)
    document = load_bound_plan(plan_path)
    if repo.resolve(merge_ref) != document["merge_sha"]:
        raise PrCliError("Checked-out merge SHA does not match the bound plan")
    if repo.gitlink(document["merge_sha"], "bin") != document.get("merge_bin_commit"):
        raise PrCliError("Merge bin gitlink does not match the bound plan")
    _verify_bound_digest(document, "merge_config_index", repo.read(document["merge_sha"], "configs/config.yaml"))
    _verify_bound_digest(document, "merge_registry", repo.read(document["merge_sha"], "gamesymbol-impact.yaml"))
    return repo, document


def verify_bound_tag_inputs(document: dict, repo: GitRepository, tag: str) -> dict:
    tag = validated_tag(tag)
    _verify_bound_digest(document, f"merge_config:{tag}", repo.read(document["merge_sha"], f"configs/{tag}.yaml"))
    config_raw = repo.read(document["merge_sha"], f"configs/{tag}.yaml")
    if config_raw is None:
        raise PrCliError(f"Merge config is missing for {tag}")
    with tempfile.TemporaryDirectory(prefix="gamesymbol-bound-artifacts-") as temporary:
        config_path = Path(temporary) / f"{tag}.yaml"
        config_path.write_bytes(config_raw)
        contract = load_contract(
            config_path,
            tag,
            Path(temporary) / "bin",
            artifactdir=Path(temporary) / "bin_artifacts",
        )
        _entries, digest = _artifact_inventory(
            repo,
            document["merge_sha"],
            tag,
            contract,
            require_complete=True,
        )
    if document.get("digests", {}).get(f"merge_artifacts:{tag}") != digest:
        raise PrCliError(f"Bound plan digest mismatch for merge_artifacts:{tag}")
    action = next((item for item in document["tags"] if item["tag"] == tag), None)
    if action is None or action.get("deleted"):
        raise PrCliError(f"Plan has no materializable action for {tag}")
    return action


def _verify_bound_digest(document: dict, key: str, raw: bytes | None) -> None:
    if document.get("digests", {}).get(key) != _sha256(raw):
        raise PrCliError(f"Bound plan digest mismatch for {key}")


def materialize_from_plan(
    *,
    repo_root: str | Path,
    plan_path: str | Path,
    tag: str,
    merge_ref: str,
    bindir: str | Path,
    artifactdir: str | Path,
) -> tuple[str, ...]:
    tag = validated_tag(tag)
    repo, document = verify_bound_plan_checkout(repo_root=repo_root, plan_path=plan_path, merge_ref=merge_ref)
    action = verify_bound_tag_inputs(document, repo, tag)
    repo_root = Path(repo_root).resolve()
    artifactdir = Path(artifactdir).resolve()
    if artifactdir == repo_root or repo_root in artifactdir.parents:
        raise PrCliError("Rebuild artifact root must be outside the source checkout")
    config_raw = repo.read(document["merge_sha"], f"configs/{tag}.yaml")
    if config_raw is None:
        raise PrCliError(f"Merge config is missing for {tag}")
    with tempfile.TemporaryDirectory(prefix="gamesymbol-pr-contract-") as temporary:
        config_path = Path(temporary) / f"{tag}.yaml"
        config_path.write_bytes(config_raw)
        merge_contract = load_contract(config_path, tag, bindir, artifactdir=artifactdir)
        unknown_nodes = set(action["analysis_nodes"]) - set(merge_contract.nodes)
        if unknown_nodes:
            raise PrCliError(f"Plan references unknown merge nodes: {', '.join(sorted(unknown_nodes))}")
        invalidated = set(action["invalidated_paths"])
        if invalidated - merge_contract.formal_paths:
            raise PrCliError("Plan references paths outside the merge contract")
        entries, _digest = _artifact_inventory(
            repo,
            document["merge_sha"],
            tag,
            merge_contract,
            require_complete=True,
        )
        game_root = merge_contract.artifact_game_root
        ensure_real_tree(artifactdir, game_root)
        game_root.mkdir(parents=True, exist_ok=True)
        if is_reparse_point(game_root):
            raise PrCliError(f"Rebuild artifact root must not be a link/reparse point: {game_root}")
        for path in list(iter_yaml_paths(game_root)):
            path.unlink()
        selected = []
        for entry in entries:
            relative = entry["path"]
            if relative in invalidated:
                continue
            raw = repo.read(document["merge_sha"], f"bin_artifacts/{tag}/{relative}")
            if raw is None:
                raise PrCliError(f"Merge artifact disappeared during materialization: {relative}")
            target = path_from_key(game_root, relative)
            if target.parent.exists() and is_reparse_point(target.parent):
                raise PrCliError(f"Refusing to materialize through a link/reparse point: {target.parent}")
            _atomic_write(target, raw)
            selected.append(relative)
        return tuple(selected)


def compare_rebuilt_artifacts(
    *,
    repo_root: str | Path,
    plan_path: str | Path,
    tag: str,
    merge_ref: str,
    bindir: str | Path,
    artifactdir: str | Path,
) -> tuple[str, ...]:
    tag = validated_tag(tag)
    repo, document = verify_bound_plan_checkout(repo_root=repo_root, plan_path=plan_path, merge_ref=merge_ref)
    verify_bound_tag_inputs(document, repo, tag)
    repo_root = Path(repo_root).resolve()
    artifactdir = Path(artifactdir).resolve()
    if artifactdir == repo_root or repo_root in artifactdir.parents:
        raise PrCliError("Rebuild artifact root must be outside the source checkout")
    config_raw = repo.read(document["merge_sha"], f"configs/{tag}.yaml")
    if config_raw is None:
        raise PrCliError(f"Merge config is missing for {tag}")
    with tempfile.TemporaryDirectory(prefix="gamesymbol-pr-compare-") as temporary:
        config_path = Path(temporary) / f"{tag}.yaml"
        config_path.write_bytes(config_raw)
        contract = load_contract(config_path, tag, bindir, artifactdir=artifactdir)
        expected, _digest = _artifact_inventory(
            repo,
            document["merge_sha"],
            tag,
            contract,
            require_complete=True,
        )
        try:
            actual_inventory = build_game_artifact_inventory(tag, config_path, artifactdir)
        except BinArtifactContractError as exc:
            raise PrCliError(f"Rebuilt artifact contract failed for {tag}: {exc}") from exc
        actual = tuple(
            {"path": entry.path, "size": entry.size, "sha256": entry.sha256} for entry in actual_inventory.entries
        )
        if actual != expected:
            raise PrCliError(f"Rebuilt artifact inventory differs from merge Git blobs for {tag}")
        for entry in expected:
            expected_raw = repo.read(document["merge_sha"], f"bin_artifacts/{tag}/{entry['path']}")
            actual_raw = path_from_key(contract.artifact_game_root, entry["path"]).read_bytes()
            if expected_raw != actual_raw:
                raise PrCliError(f"Rebuilt artifact bytes differ from merge Git blob: {tag}/{entry['path']}")
        return tuple(entry["path"] for entry in expected)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Plan and materialize trusted incremental game-symbol PR validation")
    commands = parser.add_subparsers(dest="command", required=True)
    plan = commands.add_parser("plan")
    plan.add_argument("-repo-root", default=".")
    plan.add_argument("-base-ref", required=True)
    plan.add_argument("-head-ref", required=True)
    plan.add_argument("-merge-ref", required=True)
    plan.add_argument("-bin-repo", default=None)
    plan.add_argument("-output", required=True)
    materialize = commands.add_parser("materialize")
    materialize.add_argument("-repo-root", default=".")
    materialize.add_argument("-plan", required=True)
    materialize.add_argument("-tag", required=True)
    materialize.add_argument("-merge-ref", default="HEAD")
    materialize.add_argument("-bindir", default="bin")
    materialize.add_argument("-artifactdir", default="bin_artifacts")
    compare = commands.add_parser("compare")
    compare.add_argument("-repo-root", default=".")
    compare.add_argument("-plan", required=True)
    compare.add_argument("-tag", required=True)
    compare.add_argument("-merge-ref", default="HEAD")
    compare.add_argument("-bindir", default="bin")
    compare.add_argument("-artifactdir", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "plan":
            plan = build_plan(
                repo_root=args.repo_root,
                base_ref=args.base_ref,
                head_ref=args.head_ref,
                merge_ref=args.merge_ref,
                bin_repo_root=args.bin_repo,
            )
            Path(args.output).write_bytes(plan.canonical_bytes())
        elif args.command == "materialize":
            materialize_from_plan(
                repo_root=args.repo_root,
                plan_path=args.plan,
                tag=args.tag,
                merge_ref=args.merge_ref,
                bindir=args.bindir,
                artifactdir=args.artifactdir,
            )
        else:
            compare_rebuilt_artifacts(
                repo_root=args.repo_root,
                plan_path=args.plan,
                tag=args.tag,
                merge_ref=args.merge_ref,
                bindir=args.bindir,
                artifactdir=args.artifactdir,
            )
    except (ImpactPlanningError, PrCliError, OSError, ValueError, yaml.YAMLError) as exc:
        print(f"Error: {exc}")
        return 1
    return 0
