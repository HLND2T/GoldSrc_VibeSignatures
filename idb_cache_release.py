#!/usr/bin/env python3
"""Gamever-scoped warm IDB cache driver for the release build.

Unlike ``idb_cache_workflow.py`` (which is bound to a PR ``plan.json``), this
enumerates every ``(module, platform)`` binary target declared by a game-version
analysis contract and warms/restores each group, so a release build can prepare
all game versions before ``ida_analyze_bin.py -allgamever``.
"""

from __future__ import annotations

import argparse
import time
from dataclasses import dataclass
from pathlib import Path

import yaml

from gamesymbol_snapshot_lib.config import load_contract
from ida_analyze_bin import prepare_analysis_binary
from idb_cache import (
    CACHE_SCHEMA_VERSION,
    IdbCacheError,
    build_binary_identity,
    build_cache_identity,
    probe_generation,
    prune_tag,
    restore_generation,
    verify_selection,
    warm_and_publish,
)
from idb_warm_worker import exclusive_file_lock, probe_runtime_contract
from release_workflow_lib.hashing import write_canonical_json


class IdbCacheReleaseError(ValueError):
    pass


@dataclass(frozen=True)
class BinaryGroup:
    tag: str
    platform: str
    workspace_root: Path
    binaries: tuple[dict, ...]


def _gamevers(repo_root: Path) -> list[str]:
    raw = (repo_root / "configs" / "config.yaml").read_text(encoding="utf-8")
    document = yaml.safe_load(raw) or {}
    gamevers = document.get("gamevers")
    if not isinstance(gamevers, list) or not gamevers:
        raise IdbCacheReleaseError("configs/config.yaml must declare a non-empty gamevers list")
    return [str(tag) for tag in gamevers]


def _binary_groups(repo_root: Path, bindir: Path, tag: str) -> tuple[BinaryGroup, ...]:
    contract = load_contract(repo_root / "configs" / f"{tag}.yaml", tag, bindir)
    groups: dict[tuple[str, str], list[dict]] = {}
    for (module, platform), target in sorted(contract.binary_targets.items()):
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


def _identity(group: BinaryGroup, ida_root: Path, kernel_version: str, ida_args: list[str], worker: Path) -> dict:
    first = group.workspace_root.joinpath(*Path(group.binaries[0]["path"]).parts)
    runtime = probe_runtime_contract(ida_root=ida_root, kernel_version=kernel_version, binary_path=first)
    return build_cache_identity(
        tag=group.tag,
        ida_runtime=runtime,
        normalized_ida_args=ida_args,
        binaries=list(group.binaries),
        warm_worker_path=worker,
    )


def warm_gamever(
    *,
    repo_root: Path,
    tag: str,
    bindir: Path,
    persisted_root: Path,
    ida_root: Path,
    kernel_version: str,
    ida_args: list[str],
    run_id: str,
    attempt: int,
    timeout_seconds: float,
) -> None:
    worker = Path(__file__).with_name("idb_warm_worker.py")
    lock_root = persisted_root / "idb-cache" / ".locks"
    lock_root.mkdir(parents=True, exist_ok=True)
    for group in _binary_groups(repo_root, bindir, tag):
        identity = _identity(group, ida_root, kernel_version, ida_args, worker)
        started = time.monotonic()
        with exclusive_file_lock(lock_root / f"{group.tag}.lock"):
            selection = probe_generation(persisted_root=persisted_root, identity=identity)
            hit = selection is not None
            if selection is None:
                identity_path = persisted_root / f".{group.tag}-{group.platform}-identity.json"
                try:
                    write_canonical_json(identity_path, identity)
                    selection = warm_and_publish(
                        persisted_root=persisted_root,
                        identity_path=identity_path,
                        workspace_root=group.workspace_root,
                        run_id=run_id,
                        attempt=attempt,
                        port_lock=lock_root / "ida-mcp-port.lock",
                        timeout_seconds=timeout_seconds,
                    )
                finally:
                    if identity_path.exists():
                        identity_path.unlink()
            verify_selection(persisted_root=persisted_root, selection=selection)
            prune_tag(persisted_root=persisted_root, tag=group.tag)
        print(
            f"IDB cache {'hit' if hit else 'miss'}: {group.tag}/{group.platform}; "
            f"binaries={len(group.binaries)}; wall_seconds={time.monotonic() - started:.3f}"
        )


def restore_gamever(
    *,
    repo_root: Path,
    tag: str,
    bindir: Path,
    persisted_root: Path,
    ida_root: Path,
    kernel_version: str,
    ida_args: list[str],
) -> None:
    worker = Path(__file__).with_name("idb_warm_worker.py")
    for group in _binary_groups(repo_root, bindir, tag):
        identity = _identity(group, ida_root, kernel_version, ida_args, worker)
        selection = probe_generation(persisted_root=persisted_root, identity=identity)
        if selection is None:
            raise IdbCacheReleaseError(f"no warm IDB cache generation is available for {group.tag}/{group.platform}")
        verify_selection(persisted_root=persisted_root, selection=selection)
        restore_generation(
            persisted_root=persisted_root,
            selection={
                "schema_version": CACHE_SCHEMA_VERSION,
                "tag": selection["tag"],
                "cache_key": selection["cache_key"],
                "generation": selection["generation"],
                "manifest_sha256": selection["manifest_sha256"],
            },
            workspace_root=group.workspace_root,
        )
        print(f"IDB cache restored: {group.tag}/{group.platform}")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Gamever-scoped warm IDB cache for the release build")
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("warm", "restore"):
        command = commands.add_parser(name)
        command.add_argument("-repo-root", default=".")
        command.add_argument("-gamever", required=True)
        command.add_argument("-bindir", default="bin")
        command.add_argument("-persisted-root", required=True)
        command.add_argument("-ida-root", required=True)
        command.add_argument("-kernel-version", required=True)
        command.add_argument("-ida-arg", action="append", default=[])
    warm = commands.choices["warm"]
    warm.add_argument("-run-id", required=True)
    warm.add_argument("-attempt", type=int, required=True)
    warm.add_argument("-timeout-seconds", type=float, default=3600.0)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    repo_root = Path(args.repo_root).resolve()
    bindir = (repo_root / args.bindir).resolve()
    try:
        if args.command == "warm":
            warm_gamever(
                repo_root=repo_root,
                tag=args.gamever,
                bindir=bindir,
                persisted_root=Path(args.persisted_root),
                ida_root=Path(args.ida_root),
                kernel_version=args.kernel_version,
                ida_args=list(args.ida_arg),
                run_id=args.run_id,
                attempt=args.attempt,
                timeout_seconds=args.timeout_seconds,
            )
        else:
            restore_gamever(
                repo_root=repo_root,
                tag=args.gamever,
                bindir=bindir,
                persisted_root=Path(args.persisted_root),
                ida_root=Path(args.ida_root),
                kernel_version=args.kernel_version,
                ida_args=list(args.ida_arg),
            )
    except (IdbCacheError, IdbCacheReleaseError, OSError, ValueError) as exc:
        print(f"Error: {exc}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
