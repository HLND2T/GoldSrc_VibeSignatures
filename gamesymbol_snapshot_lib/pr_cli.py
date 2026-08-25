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
from gamesymbol_snapshot_lib.analysis_sources import (
    build_source_index,
    is_analysis_source_path,
    validate_reference_consumers,
)
from gamesymbol_snapshot_lib.codec import canonical_snapshot_bytes, parse_snapshot_bytes
from gamesymbol_snapshot_lib.config import load_contract
from gamesymbol_snapshot_lib.impact_registry import parse_impact_registry
from gamesymbol_snapshot_lib.materialize import materialize_baseline
from gamesymbol_snapshot_lib.paths import metadata_filename, metadata_tag_from_filename
from gamesymbol_snapshot_lib.operations import load_snapshot_context, validate_snapshot_contract
from gamesymbol_snapshot_lib.pr_validation import (
    BoundImpactPlan,
    CACHE_MODES,
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


def _gamedata_tree_digest(repo: GitRepository, ref: str, tag: str) -> str | None:
    prefix = f"gamedata/{validated_tag(tag)}/"
    entries = []
    for path in repo.list_files(ref):
        if not path.startswith(prefix):
            continue
        raw = repo.read(ref, path)
        if raw is not None:
            entries.append({"path": path, "size": len(raw), "sha256": _sha256(raw)})
    if not entries:
        return None
    encoded = json.dumps(entries, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


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
    return load_contract(path, tag, temporary / ref.replace("/", "_") / "bin"), raw


def _snapshot(repo: GitRepository, ref: str, tag: str, contract):
    raw = repo.read(ref, f"gamesymbols/{tag}.yaml")
    if raw is None:
        return None, None, False
    try:
        document = parse_snapshot_bytes(raw, tag)
        if contract is None:
            return document, raw, False
        validate_snapshot_contract(document, contract)
        trusted = canonical_snapshot_bytes(document) == raw
        return document, raw, trusted
    except Exception:
        return None, raw, False


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


def _binary_metadata_trusted(document: dict | None, contract) -> bool:
    return bool(document is not None and contract is not None and contract.binary_targets)


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
    cache_mode: str = "cold",
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
            if path.startswith("gamesymbols/"):
                metadata_tag = metadata_tag_from_filename(path.removeprefix("gamesymbols/"))
                if metadata_tag is not None and metadata_tag not in known_tags:
                    raise ImpactPlanningError(f"Metadata companion has no configured tag: {path}")
            parts = path.split("/")
            if parts[0] == "gamedata" and len(parts) >= 3:
                try:
                    gamedata_tag = validated_tag(parts[1])
                except ValueError as exc:
                    raise ImpactPlanningError(f"Invalid tracked gamedata path: {path}") from exc
                if gamedata_tag not in known_tags:
                    raise ImpactPlanningError(f"Tracked gamedata has no configured tag: {path}")

    # A tag removed from configs/config.yaml must delete its committed
    # gamesymbols/gamedata payloads in the same PR; release owns those outputs.
    for tag in base_tags:
        if tag in merge_tags:
            continue
        for path in (f"gamesymbols/{tag}.yaml", f"gamesymbols/{metadata_filename(tag)}"):
            if repo.read(merge_sha, path) is not None:
                raise ImpactPlanningError(f"Removed tag {tag} still has committed snapshot: {path}")
        if _gamedata_tree_digest(repo, merge_sha, tag) is not None:
            raise ImpactPlanningError(f"Removed tag {tag} still has committed gamedata")

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
        snapshots = {}
        for tag in ordered_tags:
            base_contracts[tag], base_config_raw = _contract(repo, base_sha, tag, temporary)
            merge_contracts[tag], merge_config_raw = _contract(repo, merge_sha, tag, temporary)
            digests[f"base_config:{tag}"] = _sha256(base_config_raw)
            digests[f"merge_config:{tag}"] = _sha256(merge_config_raw)
            if base_contracts[tag] is not None:
                base_sources[tag] = build_source_index(base_contracts[tag], base_tree)
            if merge_contracts[tag] is not None:
                merge_sources[tag] = build_source_index(merge_contracts[tag], merge_tree)
            base_document, base_snapshot_raw, base_contract_trusted = _snapshot(
                repo, base_sha, tag, base_contracts[tag]
            )
            merge_document, merge_snapshot_raw, _merge_trusted = _snapshot(repo, merge_sha, tag, merge_contracts[tag])
            digests[f"base_snapshot:{tag}"] = _sha256(base_snapshot_raw)
            digests[f"merge_snapshot:{tag}"] = _sha256(merge_snapshot_raw)
            digests[f"base_metadata:{tag}"] = _sha256(repo.read(base_sha, f"gamesymbols/{metadata_filename(tag)}"))
            digests[f"merge_metadata:{tag}"] = _sha256(repo.read(merge_sha, f"gamesymbols/{metadata_filename(tag)}"))
            digests[f"base_gamedata:{tag}"] = _gamedata_tree_digest(repo, base_sha, tag)
            digests[f"merge_gamedata:{tag}"] = _gamedata_tree_digest(repo, merge_sha, tag)
            snapshots[tag] = (base_document, merge_document, base_contract_trusted)

        validate_reference_consumers(merge_tree, list(merge_sources.values()))
        for path in sorted({path for change in changes for path in change.paths if is_analysis_source_path(path)}):
            if not any(index.owners(path) for index in (*base_sources.values(), *merge_sources.values())):
                raise ImpactPlanningError(f"Changed analysis source has no mapped consumer: {path}")
        for tag in ordered_tags:
            base_document, merge_document, base_contract_trusted = snapshots[tag]
            trusted = base_contract_trusted and _binary_metadata_trusted(base_document, base_contracts[tag])
            impact = plan_tag_impact(
                tag=tag,
                base_contract=base_contracts[tag],
                merge_contract=merge_contracts[tag],
                changed_paths=changes,
                base_sources=base_sources.get(tag),
                merge_sources=merge_sources.get(tag),
                base_rules=base_rules,
                merge_rules=merge_rules,
                metadata_changed=any(f"gamesymbols/{metadata_filename(tag)}" in change.paths for change in changes),
                gamedata_changed=any(
                    any(path.startswith(f"gamedata/{tag}/") for path in change.paths) for change in changes
                ),
                binary_changed_pairs=_binary_changes(
                    tag=tag,
                    base_contract=base_contracts[tag],
                    merge_contract=merge_contracts[tag],
                    bin_repo=bin_repo,
                    base_commit=base_bin,
                    merge_commit=merge_bin,
                ),
                base_snapshot_trusted=trusted,
                fail_unmapped_analysis=False,
            )
            if impact.has_actions:
                impacts.append(impact)
    return BoundImpactPlan(base_sha, head_sha, merge_sha, base_bin, merge_bin, tuple(impacts), digests, cache_mode)


def load_bound_plan(path: str | Path) -> dict:
    document = json.loads(Path(path).read_text(encoding="utf-8"))
    if (
        not isinstance(document, dict)
        or document.get("schema_version") != 2
        or document.get("cache_mode") not in CACHE_MODES
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
    _verify_bound_digest(
        document,
        f"merge_snapshot:{tag}",
        repo.read(document["merge_sha"], f"gamesymbols/{tag}.yaml"),
    )
    _verify_bound_digest(
        document,
        f"merge_metadata:{tag}",
        repo.read(document["merge_sha"], f"gamesymbols/{metadata_filename(tag)}"),
    )
    _verify_bound_gamedata(document, f"merge_gamedata:{tag}", repo, document["merge_sha"], tag)
    action = next((item for item in document["tags"] if item["tag"] == tag), None)
    if action is None or action.get("deleted"):
        raise PrCliError(f"Plan has no materializable action for {tag}")
    return action


def _verify_bound_digest(document: dict, key: str, raw: bytes | None) -> None:
    if document.get("digests", {}).get(key) != _sha256(raw):
        raise PrCliError(f"Bound plan digest mismatch for {key}")


def _verify_bound_gamedata(document: dict, key: str, repo: GitRepository, ref: str, tag: str) -> None:
    if document.get("digests", {}).get(key) != _gamedata_tree_digest(repo, ref, tag):
        raise PrCliError(f"Bound plan digest mismatch for {key}")


def materialize_from_plan(
    *,
    repo_root: str | Path,
    plan_path: str | Path,
    tag: str,
    merge_ref: str,
    bindir: str | Path,
) -> tuple[str, ...]:
    tag = validated_tag(tag)
    repo, document = verify_bound_plan_checkout(repo_root=repo_root, plan_path=plan_path, merge_ref=merge_ref)
    action = verify_bound_tag_inputs(document, repo, tag)
    config_path = Path(repo_root) / "configs" / f"{tag}.yaml"
    merge_contract = load_contract(config_path, tag, bindir)
    unknown_nodes = set(action["analysis_nodes"]) - set(merge_contract.nodes)
    if unknown_nodes:
        raise PrCliError(f"Plan references unknown merge nodes: {', '.join(sorted(unknown_nodes))}")
    invalidated = tuple(action["invalidated_paths"])
    if set(invalidated) - merge_contract.formal_paths:
        raise PrCliError("Plan references paths outside the merge contract")
    base = None
    if action["mode"] == "incremental":
        with tempfile.TemporaryDirectory(prefix="gamesymbol-pr-base-") as temporary:
            base_config_raw = repo.read(document["base_sha"], f"configs/{tag}.yaml")
            base_snapshot_raw = repo.read(document["base_sha"], f"gamesymbols/{tag}.yaml")
            _verify_bound_digest(document, f"base_config:{tag}", base_config_raw)
            _verify_bound_digest(document, f"base_snapshot:{tag}", base_snapshot_raw)
            _verify_bound_digest(
                document,
                f"base_metadata:{tag}",
                repo.read(document["base_sha"], f"gamesymbols/{metadata_filename(tag)}"),
            )
            _verify_bound_gamedata(document, f"base_gamedata:{tag}", repo, document["base_sha"], tag)
            if base_config_raw is None or base_snapshot_raw is None:
                raise PrCliError("Incremental plan is missing its bound base contract")
            temporary_root = Path(temporary)
            base_config = temporary_root / f"{tag}.yaml"
            base_snapshot = temporary_root / f"{tag}.snapshot.yaml"
            base_config.write_bytes(base_config_raw)
            base_snapshot.write_bytes(base_snapshot_raw)
            base = load_snapshot_context(base_snapshot, base_config, tag, bindir)
            return materialize_baseline(
                base=base,
                merge_contract=merge_contract,
                bindir=bindir,
                invalidated_paths=invalidated,
                mode=action["mode"],
            )
    return materialize_baseline(
        base=None,
        merge_contract=merge_contract,
        bindir=bindir,
        invalidated_paths=invalidated,
        mode=action["mode"],
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Plan and materialize trusted incremental game-symbol PR validation")
    commands = parser.add_subparsers(dest="command", required=True)
    plan = commands.add_parser("plan")
    plan.add_argument("-repo-root", default=".")
    plan.add_argument("-base-ref", required=True)
    plan.add_argument("-head-ref", required=True)
    plan.add_argument("-merge-ref", required=True)
    plan.add_argument("-bin-repo", default=None)
    plan.add_argument("-cache-mode", choices=tuple(sorted(CACHE_MODES)), required=True)
    plan.add_argument("-output", required=True)
    materialize = commands.add_parser("materialize")
    materialize.add_argument("-repo-root", default=".")
    materialize.add_argument("-plan", required=True)
    materialize.add_argument("-tag", required=True)
    materialize.add_argument("-merge-ref", default="HEAD")
    materialize.add_argument("-bindir", default="bin")
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
                cache_mode=args.cache_mode,
            )
            Path(args.output).write_bytes(plan.canonical_bytes())
        else:
            materialize_from_plan(
                repo_root=args.repo_root,
                plan_path=args.plan,
                tag=args.tag,
                merge_ref=args.merge_ref,
                bindir=args.bindir,
            )
    except (ImpactPlanningError, PrCliError, OSError, ValueError, yaml.YAMLError) as exc:
        print(f"Error: {exc}")
        return 1
    return 0
