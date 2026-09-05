#!/usr/bin/env python3
"""Release-scoped exact warm IDB cache selection driver.

Unlike ``idb_cache_workflow.py`` (which is bound to a PR ``plan.json``), this enumerates
every ``(module, platform)`` binary target declared by every game-version analysis
contract in ``configs/config.yaml``, so one producer run can warm all game versions before
``ida_analyze_bin.py -allgamever``.

The producer publishes immutable generations and writes a canonical ``cache-selection.json``
plus independent SHA-256 evidence. The consumer runs in a different, freshly materialized
workspace, verifies that selection against its own checkout, and restores those exact
generations. The consumer never probes ``READY.json``: a producer for another release may
legitimately advance READY in between, and the current run must stay bound to the exact
generations its own producer published.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

import yaml

from gamesymbol_snapshot_lib.config import load_contract
from gamesymbol_snapshot_lib.pr_validation import CACHE_MODE_WARM
from ida_analyze_bin import prepare_analysis_binary
from idb_cache import (
    DEFAULT_WORKER_TIMEOUT_SECONDS,
    IdbCacheError,
    build_binary_identity,
    build_cache_identity,
)
from idb_cache_locks import producer_lock
from idb_cache_selection import (
    IdbCacheSelectionError,
    entry_sort_key,
    prepare_selection_entries,
    read_selection_with_evidence,
    restore_selection_entries,
    validate_persisted_workspace,
    validate_selection_entries,
    write_selection_with_evidence,
)
from release_workflow_lib.hashing import canonical_json_bytes
from warmup_memory import ProducerMemoryOwner, producer_memory_owner_from_environment

RELEASE_SELECTION_SCHEMA_VERSION = 1
RELEASE_SELECTION_KEYS = {"schema_version", "cache_mode", "source_sha", "bin_commit", "entries"}
COMMIT_SHA_RE = re.compile(r"^[0-9a-f]{40}$", re.ASCII)
GITLINK_MODE = "160000"


class IdbCacheReleaseError(ValueError):
    pass


@dataclass(frozen=True)
class BinaryGroup:
    tag: str
    platform: str
    workspace_root: Path
    binaries: tuple[dict, ...]


def _git_output(repo_root: Path, arguments: list[str]) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo_root), *arguments],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise IdbCacheReleaseError(result.stderr.strip() or f"git {' '.join(arguments)} failed")
    return result.stdout.strip()


def _validated_commit_sha(value: object, context: str) -> str:
    normalized = str(value).strip().lower()
    if not COMMIT_SHA_RE.fullmatch(normalized):
        raise IdbCacheReleaseError(f"{context} must be a full 40-hex commit SHA")
    return normalized


def checkout_source_sha(repo_root: Path) -> str:
    return _validated_commit_sha(_git_output(repo_root, ["rev-parse", "HEAD"]), "checkout HEAD")


def checkout_bin_commit(repo_root: Path, bindir_name: str) -> str:
    record = _git_output(repo_root, ["ls-tree", "HEAD", "--", bindir_name])
    if not record:
        raise IdbCacheReleaseError(f"source tree declares no {bindir_name} gitlink")
    metadata = record.split("\t", 1)[0].split()
    if len(metadata) != 3 or metadata[0] != GITLINK_MODE:
        raise IdbCacheReleaseError(f"{bindir_name} must be a submodule gitlink in the source tree")
    return _validated_commit_sha(metadata[2], f"{bindir_name} gitlink")


def _gamevers(repo_root: Path) -> list[str]:
    raw = (repo_root / "configs" / "config.yaml").read_text(encoding="utf-8")
    document = yaml.safe_load(raw) or {}
    gamevers = document.get("gamevers")
    if not isinstance(gamevers, list) or not gamevers:
        raise IdbCacheReleaseError("configs/config.yaml must declare a non-empty gamevers list")
    return [str(tag) for tag in gamevers]


def _tag_binary_groups(repo_root: Path, bindir: Path, tag: str) -> tuple[BinaryGroup, ...]:
    contract = load_contract(
        repo_root / "configs" / f"{tag}.yaml",
        tag,
        bindir,
        artifactdir=repo_root / "bin_artifacts",
    )
    groups: dict[tuple[str, str], list[dict]] = {}
    for (module, platform), target in sorted(contract.binary_targets.items()):
        original = contract.binary_game_root / module / target.binary_name
        binary = prepare_analysis_binary(original, platform)
        relative = binary.relative_to(contract.binary_game_root).as_posix()
        groups.setdefault((tag, platform), []).append(
            build_binary_identity(
                workspace_root=contract.binary_game_root,
                module=module,
                platform=platform,
                relative_path=relative,
            )
        )
    return tuple(
        BinaryGroup(
            tag=tag,
            platform=platform,
            workspace_root=bindir / tag,
            binaries=tuple(
                sorted(records, key=lambda item: (item["module"].encode("utf-8"), item["path"].encode("utf-8")))
            ),
        )
        for (tag, platform), records in sorted(groups.items(), key=lambda item: (item[0][0], item[0][1]))
    )


def release_binary_groups(repo_root: Path, bindir: Path) -> tuple[BinaryGroup, ...]:
    """Enumerate every binary group the current release configs declare, in canonical order."""
    groups = [group for tag in _gamevers(repo_root) for group in _tag_binary_groups(repo_root, bindir, tag)]
    if not groups:
        raise IdbCacheReleaseError("release configs declare no warmable binary groups")
    return tuple(sorted(groups, key=lambda group: (group.tag.encode("utf-8"), group.platform.encode("utf-8"))))


def _release_identities(
    *,
    groups: tuple[BinaryGroup, ...],
    kernel_version: str,
) -> dict[tuple[str, str], dict]:
    worker = Path(__file__).with_name("idb_warm_worker.py")
    identities = {}
    for group in groups:
        identities[(group.tag, group.platform)] = build_cache_identity(
            tag=group.tag,
            ida_runtime={"kernel_version": str(kernel_version).strip()},
            binaries=list(group.binaries),
            warm_worker_path=worker,
        )
    return identities


@dataclass(frozen=True)
class ReleaseCacheContext:
    repo_root: Path
    bindir: Path
    persisted_root: Path
    source_sha: str
    bin_commit: str
    groups: tuple[BinaryGroup, ...]
    identities: dict[tuple[str, str], dict]


def _release_context(
    *,
    repo_root: str | Path,
    bindir: str | Path,
    persisted_root: str | Path,
    kernel_version: str,
    source_sha: str | None,
) -> ReleaseCacheContext:
    root = Path(repo_root).resolve()
    binary_root = (root / bindir).resolve()
    persisted = validate_persisted_workspace(persisted_root, root)
    try:
        bindir_name = binary_root.relative_to(root).as_posix()
    except ValueError as exc:
        raise IdbCacheReleaseError("Release cache workflow requires bindir inside the checkout") from exc
    checkout_sha = checkout_source_sha(root)
    if source_sha is not None and _validated_commit_sha(source_sha, "source_sha") != checkout_sha:
        raise IdbCacheReleaseError(f"Release checkout drifted from the bound source SHA: {checkout_sha}")
    groups = release_binary_groups(root, binary_root)
    return ReleaseCacheContext(
        repo_root=root,
        bindir=binary_root,
        persisted_root=persisted,
        source_sha=checkout_sha,
        bin_commit=checkout_bin_commit(root, bindir_name),
        groups=groups,
        identities=_release_identities(
            groups=groups,
            kernel_version=kernel_version,
        ),
    )


def _selection_document(context: ReleaseCacheContext, entries: list[dict]) -> dict:
    return {
        "schema_version": RELEASE_SELECTION_SCHEMA_VERSION,
        "cache_mode": CACHE_MODE_WARM,
        "source_sha": context.source_sha,
        "bin_commit": context.bin_commit,
        "entries": sorted(entries, key=entry_sort_key),
    }


def validate_release_selection(*, document: object, context: ReleaseCacheContext, raw: bytes | None = None) -> dict:
    if (
        not isinstance(document, dict)
        or set(document) != RELEASE_SELECTION_KEYS
        or document["schema_version"] != RELEASE_SELECTION_SCHEMA_VERSION
        or document["cache_mode"] != CACHE_MODE_WARM
    ):
        raise IdbCacheReleaseError("Release cache selection has unexpected fields, schema, or mode")
    if document["source_sha"] != context.source_sha:
        raise IdbCacheReleaseError("Release cache selection does not bind the current source checkout")
    if document["bin_commit"] != context.bin_commit:
        raise IdbCacheReleaseError("Release cache selection does not bind the current bin gitlink")
    validate_selection_entries(
        entries=document["entries"],
        identities=context.identities,
        persisted_root=context.persisted_root,
    )
    if raw is not None and canonical_json_bytes(document) != raw:
        raise IdbCacheReleaseError("Release cache selection is not canonical JSON")
    return document


def prepare_release_selection(
    *,
    repo_root: str | Path,
    bindir: str | Path,
    persisted_root: str | Path,
    kernel_version: str,
    ida_python_executable: str | Path,
    source_sha: str | None,
    run_id: str,
    attempt: int,
    max_concurrency: int | None,
    worker_timeout_seconds: float,
    output_path: str | Path,
    output_sha256_path: str | Path,
    producer_memory: ProducerMemoryOwner | None = None,
) -> dict:
    root = Path(repo_root).resolve()
    persisted = validate_persisted_workspace(persisted_root, root)
    producer_lock_started = time.monotonic()
    with producer_lock(persisted, timeout_seconds=None):
        print(f"IDB cache producer lock acquired: wait_seconds={time.monotonic() - producer_lock_started:.3f}")
        context = _release_context(
            repo_root=root,
            bindir=bindir,
            persisted_root=persisted,
            kernel_version=kernel_version,
            source_sha=source_sha,
        )
        print(
            f"IDB cache producer scope: release-all; source_sha={context.source_sha}; "
            f"bin_commit={context.bin_commit}; groups={len(context.groups)}"
        )
        entries = prepare_selection_entries(
            groups=context.groups,
            identities=context.identities,
            persisted_root=context.persisted_root,
            run_id=run_id,
            attempt=attempt,
            ida_python_executable=ida_python_executable,
            max_concurrency=max_concurrency,
            worker_timeout_seconds=worker_timeout_seconds,
            producer_memory=producer_memory or producer_memory_owner_from_environment(),
        )
        document = _selection_document(context, entries)
        validate_release_selection(document=document, context=context)
        raw, digest = write_selection_with_evidence(
            document=document,
            output_path=output_path,
            output_sha256_path=output_sha256_path,
        )
        validate_release_selection(document=json.loads(raw), context=context, raw=raw)
        print(f"Release cache selection SHA-256: {digest}")
        return document


def verify_release_selection_file(
    *,
    repo_root: str | Path,
    bindir: str | Path,
    persisted_root: str | Path,
    kernel_version: str,
    source_sha: str | None,
    selection_path: str | Path,
    selection_sha256_path: str | Path,
) -> tuple[dict, ReleaseCacheContext]:
    context = _release_context(
        repo_root=repo_root,
        bindir=bindir,
        persisted_root=persisted_root,
        kernel_version=kernel_version,
        source_sha=source_sha,
    )
    document, raw, digest = read_selection_with_evidence(
        selection_path=selection_path,
        selection_sha256_path=selection_sha256_path,
    )
    validate_release_selection(document=document, context=context, raw=raw)
    print(
        f"Release cache selection verified: SHA-256={digest}; source_sha={context.source_sha}; "
        f"bin_commit={context.bin_commit}; groups={len(context.groups)}"
    )
    return document, context


def restore_release_selection(**kwargs) -> dict:
    document, context = verify_release_selection_file(**kwargs)
    restore_selection_entries(
        entries=document["entries"],
        groups=context.groups,
        persisted_root=context.persisted_root,
    )
    return document


def _common_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("-repo-root", default=".")
    parser.add_argument("-bindir", default="bin")
    parser.add_argument("-persisted-root", required=True)
    parser.add_argument("-kernel-version", required=True)
    parser.add_argument("-source-sha")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Release-scoped exact warm IDB cache selection")
    commands = parser.add_subparsers(dest="command", required=True)
    prepare = commands.add_parser("prepare")
    _common_arguments(prepare)
    prepare.add_argument("--ida-python", required=True)
    prepare.add_argument("--max-concurrency", type=int)
    prepare.add_argument(
        "--worker-timeout-seconds",
        type=float,
        default=DEFAULT_WORKER_TIMEOUT_SECONDS,
    )
    prepare.add_argument("-run-id", required=True)
    prepare.add_argument("-attempt", type=int, required=True)
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
        "bindir": args.bindir,
        "persisted_root": args.persisted_root,
        "kernel_version": args.kernel_version,
        "source_sha": args.source_sha,
        "selection_path": args.selection,
        "selection_sha256_path": args.selection_sha256,
    }


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "prepare":
            prepare_release_selection(
                repo_root=args.repo_root,
                bindir=args.bindir,
                persisted_root=args.persisted_root,
                kernel_version=args.kernel_version,
                ida_python_executable=args.ida_python,
                source_sha=args.source_sha,
                run_id=args.run_id,
                attempt=args.attempt,
                max_concurrency=args.max_concurrency,
                worker_timeout_seconds=args.worker_timeout_seconds,
                output_path=args.output,
                output_sha256_path=args.output_sha256,
            )
        elif args.command == "verify":
            verify_release_selection_file(**_verification_kwargs(args))
        else:
            restore_release_selection(**_verification_kwargs(args))
    except (IdbCacheError, IdbCacheSelectionError, IdbCacheReleaseError, OSError, ValueError) as exc:
        print(f"Error: {exc}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
