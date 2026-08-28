#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path

from gamesymbol_snapshot_lib.config import load_contract
from gamesymbol_snapshot_lib.pr_cli import (
    PrCliError,
    verify_bound_plan_checkout,
    verify_bound_tag_inputs,
)
from gamesymbol_snapshot_lib.pr_validation import CACHE_MODE_WARM
from ida_analyze_bin import prepare_analysis_binary
from idb_cache import (
    IdbCacheError,
    build_binary_identity,
    build_cache_identity,
)
from idb_cache_selection import (
    SELECTION_ENTRY_KEYS,
    IdbCacheSelectionError,
    entry_sort_key,
    prepare_selection_entries,
    read_selection_with_evidence,
    restore_selection_entries,
    validate_persisted_workspace,
    validate_selection_entries,
    write_selection_with_evidence,
)
from idb_warm_worker import probe_runtime_contract
from release_workflow_lib.hashing import canonical_json_bytes

CACHE_SELECTION_SCHEMA_VERSION = 1
CACHE_SELECTION_KEYS = {
    "schema_version",
    "cache_mode",
    "plan_sha256",
    "merge_sha",
    "merge_bin_commit",
    "entries",
}
CACHE_SELECTION_ENTRY_KEYS = SELECTION_ENTRY_KEYS


class IdbCacheWorkflowError(IdbCacheSelectionError):
    pass


@dataclass(frozen=True)
class SelectedBinaryGroup:
    tag: str
    platform: str
    workspace_root: Path
    binaries: tuple[dict, ...]


def _selected_binary_groups(*, document: dict, repo_root: Path, bindir: Path, repo) -> tuple[SelectedBinaryGroup, ...]:
    if document.get("cache_mode") != CACHE_MODE_WARM:
        raise IdbCacheWorkflowError("Warm cache preparation requires a plan bound to cache_mode=warm")
    checkout = repo_root.resolve()
    binary_root = bindir.resolve()
    if binary_root != (checkout / "bin").resolve():
        raise IdbCacheWorkflowError("Self-hosted cache workflow requires the checked-out bin submodule")
    groups: dict[tuple[str, str], list[dict]] = {}
    for action in document.get("tags", []):
        node_ids = tuple(action.get("analysis_nodes", ()))
        if not node_ids:
            continue
        tag = action.get("tag")
        verified_action = verify_bound_tag_inputs(document, repo, tag)
        if tuple(verified_action.get("analysis_nodes", ())) != node_ids:
            raise IdbCacheWorkflowError(f"Bound analysis node list changed for {tag}")
        contract = load_contract(checkout / "configs" / f"{tag}.yaml", tag, binary_root)
        unknown = set(node_ids) - set(contract.nodes)
        if unknown:
            raise IdbCacheWorkflowError(
                f"Plan references unknown cache node(s) for {tag}: {', '.join(sorted(unknown))}"
            )
        pairs = sorted(
            {(contract.nodes[node_id].module_name, contract.nodes[node_id].platform) for node_id in node_ids},
            key=lambda item: (item[1], item[0].encode("utf-8")),
        )
        for module, platform in pairs:
            target = contract.binary_targets[(module, platform)]
            original = contract.game_root / module / target.binary_name
            binary = prepare_analysis_binary(original, platform)
            relative = binary.relative_to(contract.game_root).as_posix()
            groups.setdefault((tag, platform), []).append(
                build_binary_identity(
                    workspace_root=contract.game_root,
                    module=module,
                    platform=platform,
                    relative_path=relative,
                )
            )
    return tuple(
        SelectedBinaryGroup(
            tag=tag,
            platform=platform,
            workspace_root=binary_root / tag,
            binaries=tuple(
                sorted(records, key=lambda item: (item["module"].encode("utf-8"), item["path"].encode("utf-8")))
            ),
        )
        for (tag, platform), records in sorted(groups.items(), key=lambda item: (item[0][0], item[0][1]))
    )


def selected_binary_groups(
    *, repo_root: str | Path, plan_path: str | Path, merge_ref: str = "HEAD", bindir: str | Path = "bin"
) -> tuple[SelectedBinaryGroup, ...]:
    root = Path(repo_root).resolve()
    repo, document = verify_bound_plan_checkout(repo_root=root, plan_path=plan_path, merge_ref=merge_ref)
    return _selected_binary_groups(document=document, repo_root=root, bindir=root / bindir, repo=repo)


def _expected_identities(
    *,
    groups: tuple[SelectedBinaryGroup, ...],
    ida_root: str | Path,
    kernel_version: str,
    normalized_ida_args: list[str],
) -> dict[tuple[str, str], dict]:
    worker = Path(__file__).with_name("idb_warm_worker.py")
    identities = {}
    for group in groups:
        first = group.workspace_root.joinpath(*Path(group.binaries[0]["path"]).parts)
        runtime = probe_runtime_contract(
            ida_root=ida_root,
            kernel_version=kernel_version,
            binary_path=first,
        )
        identities[(group.tag, group.platform)] = build_cache_identity(
            tag=group.tag,
            ida_runtime=runtime,
            normalized_ida_args=normalized_ida_args,
            binaries=list(group.binaries),
            warm_worker_path=worker,
        )
    return identities


def _selection_document(plan: dict, entries: list[dict]) -> dict:
    return {
        "schema_version": CACHE_SELECTION_SCHEMA_VERSION,
        "cache_mode": CACHE_MODE_WARM,
        "plan_sha256": plan["plan_sha256"],
        "merge_sha": plan["merge_sha"],
        "merge_bin_commit": plan.get("merge_bin_commit"),
        "entries": sorted(entries, key=entry_sort_key),
    }


def validate_cache_selection(
    *,
    document: object,
    plan: dict,
    groups: tuple[SelectedBinaryGroup, ...],
    identities: dict[tuple[str, str], dict],
    persisted_root: str | Path,
    raw: bytes | None = None,
) -> dict:
    if (
        not isinstance(document, dict)
        or set(document) != CACHE_SELECTION_KEYS
        or document["schema_version"] != CACHE_SELECTION_SCHEMA_VERSION
        or document["cache_mode"] != CACHE_MODE_WARM
    ):
        raise IdbCacheWorkflowError("Cache selection has unexpected fields, schema, or mode")
    for field in ("plan_sha256", "merge_sha", "merge_bin_commit"):
        if document[field] != plan.get(field):
            raise IdbCacheWorkflowError(f"Cache selection does not bind plan field {field}")
    expected = {(group.tag, group.platform) for group in groups}
    if set(identities) != expected:
        raise IdbCacheWorkflowError("Bound plan groups and pinned runtime identities disagree")
    validate_selection_entries(
        entries=document["entries"],
        identities=identities,
        persisted_root=persisted_root,
    )
    if raw is not None and canonical_json_bytes(document) != raw:
        raise IdbCacheWorkflowError("Cache selection is not canonical JSON")
    return document


def prepare_cache_selection(
    *,
    repo_root: str | Path,
    plan_path: str | Path,
    merge_ref: str,
    bindir: str | Path,
    persisted_root: str | Path,
    ida_root: str | Path,
    kernel_version: str,
    normalized_ida_args: list[str],
    run_id: str,
    attempt: int,
    timeout_seconds: float,
    output_path: str | Path,
    output_sha256_path: str | Path,
) -> dict:
    root = Path(repo_root).resolve()
    persisted = validate_persisted_workspace(persisted_root, root)
    repo, plan = verify_bound_plan_checkout(repo_root=root, plan_path=plan_path, merge_ref=merge_ref)
    groups = _selected_binary_groups(document=plan, repo_root=root, bindir=root / bindir, repo=repo)
    if not groups:
        raise IdbCacheWorkflowError("Warm plan selected no binary groups")
    identities = _expected_identities(
        groups=groups,
        ida_root=ida_root,
        kernel_version=kernel_version,
        normalized_ida_args=normalized_ida_args,
    )
    entries = prepare_selection_entries(
        groups=groups,
        identities=identities,
        persisted_root=persisted,
        run_id=run_id,
        attempt=attempt,
        timeout_seconds=timeout_seconds,
    )
    document = _selection_document(plan, entries)
    validate_cache_selection(
        document=document,
        plan=plan,
        groups=groups,
        identities=identities,
        persisted_root=persisted,
    )
    raw, digest = write_selection_with_evidence(
        document=document,
        output_path=output_path,
        output_sha256_path=output_sha256_path,
    )
    validate_cache_selection(
        document=json.loads(raw),
        plan=plan,
        groups=groups,
        identities=identities,
        persisted_root=persisted,
        raw=raw,
    )
    print(f"Cache selection SHA-256: {digest}")
    return document


def verify_cache_selection_file(
    *,
    repo_root: str | Path,
    plan_path: str | Path,
    merge_ref: str,
    bindir: str | Path,
    persisted_root: str | Path,
    ida_root: str | Path,
    kernel_version: str,
    normalized_ida_args: list[str],
    selection_path: str | Path,
    selection_sha256_path: str | Path,
) -> tuple[dict, tuple[SelectedBinaryGroup, ...]]:
    root = Path(repo_root).resolve()
    persisted = validate_persisted_workspace(persisted_root, root)
    repo, plan = verify_bound_plan_checkout(repo_root=root, plan_path=plan_path, merge_ref=merge_ref)
    groups = _selected_binary_groups(document=plan, repo_root=root, bindir=root / bindir, repo=repo)
    identities = _expected_identities(
        groups=groups,
        ida_root=ida_root,
        kernel_version=kernel_version,
        normalized_ida_args=normalized_ida_args,
    )
    document, raw, _digest = read_selection_with_evidence(
        selection_path=selection_path,
        selection_sha256_path=selection_sha256_path,
    )
    return (
        validate_cache_selection(
            document=document,
            plan=plan,
            groups=groups,
            identities=identities,
            persisted_root=persisted,
            raw=raw,
        ),
        groups,
    )


def restore_cache_selection(**kwargs) -> dict:
    document, groups = verify_cache_selection_file(**kwargs)
    restore_selection_entries(
        entries=document["entries"],
        groups=groups,
        persisted_root=kwargs["persisted_root"],
    )
    return document


def _common_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("-repo-root", default=".")
    parser.add_argument("-plan", required=True)
    parser.add_argument("-merge-ref", default="HEAD")
    parser.add_argument("-bindir", default="bin")
    parser.add_argument("-persisted-root", required=True)
    parser.add_argument("-ida-root", required=True)
    parser.add_argument("-kernel-version", required=True)
    parser.add_argument("-ida-arg", action="append", default=[])


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Bound warm/cold IDB cache workflow orchestration")
    commands = parser.add_subparsers(dest="command", required=True)
    prepare = commands.add_parser("prepare")
    _common_arguments(prepare)
    prepare.add_argument("-run-id", required=True)
    prepare.add_argument("-attempt", type=int, required=True)
    prepare.add_argument("-timeout-seconds", type=float, default=3600.0)
    prepare.add_argument("-output", required=True)
    prepare.add_argument("-output-sha256", required=True)
    for name in ("verify", "restore"):
        command = commands.add_parser(name)
        _common_arguments(command)
        command.add_argument("-selection", required=True)
        command.add_argument("-selection-sha256", required=True)
    return parser


def _verification_kwargs(args) -> dict:
    return {
        "repo_root": args.repo_root,
        "plan_path": args.plan,
        "merge_ref": args.merge_ref,
        "bindir": args.bindir,
        "persisted_root": args.persisted_root,
        "ida_root": args.ida_root,
        "kernel_version": args.kernel_version,
        "normalized_ida_args": list(args.ida_arg),
        "selection_path": args.selection,
        "selection_sha256_path": args.selection_sha256,
    }


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "prepare":
            prepare_cache_selection(
                repo_root=args.repo_root,
                plan_path=args.plan,
                merge_ref=args.merge_ref,
                bindir=args.bindir,
                persisted_root=args.persisted_root,
                ida_root=args.ida_root,
                kernel_version=args.kernel_version,
                normalized_ida_args=list(args.ida_arg),
                run_id=args.run_id,
                attempt=args.attempt,
                timeout_seconds=args.timeout_seconds,
                output_path=args.output,
                output_sha256_path=args.output_sha256,
            )
        elif args.command == "verify":
            verify_cache_selection_file(**_verification_kwargs(args))
        else:
            restore_cache_selection(**_verification_kwargs(args))
    except (IdbCacheError, IdbCacheSelectionError, PrCliError, OSError, ValueError) as exc:
        print(f"Error: {exc}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
