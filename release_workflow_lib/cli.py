"""Command-line entry point for binary-only accepted-bin materialization."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import yaml

from release_workflow_lib.accepted_bin import cleanup_legacy_accepted_yaml, materialize_accepted_bin
from release_workflow_lib.errors import ReleaseWorkflowError


def _materialization_gamevers(args) -> list[str]:
    if args.all_gamevers == bool(args.gamever):
        raise ReleaseWorkflowError("materialize-accepted-bin requires either --all-gamevers or --gamever")
    if args.gamever:
        return sorted(set(args.gamever))
    document = yaml.safe_load(Path(args.repo_root, "configs", "config.yaml").read_text(encoding="utf-8")) or {}
    gamevers = document.get("gamevers")
    if not isinstance(gamevers, list) or not gamevers:
        raise ReleaseWorkflowError("configs/config.yaml must declare a non-empty gamevers list")
    return sorted({str(gamever) for gamever in gamevers})


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    materialize = commands.add_parser("materialize-accepted-bin")
    materialize.add_argument("--repo-root", default=".")
    materialize.add_argument("--persisted-root", required=True)
    materialize.add_argument("--bindir", default="bin")
    materialize.add_argument("--gamever", action="append", default=[])
    materialize.add_argument("--all-gamevers", action="store_true")
    cleanup = commands.add_parser("cleanup-legacy-accepted-yaml")
    cleanup.add_argument("--repo-root", default=".")
    cleanup.add_argument("--persisted-root", required=True)
    cleanup.add_argument("--bindir", default="bin")
    cleanup.add_argument("--gamever", required=True)
    cleanup.add_argument("--cutover-id", required=True)
    return parser


def main(argv=None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "cleanup-legacy-accepted-yaml":
            result = cleanup_legacy_accepted_yaml(
                repo_root=args.repo_root,
                persisted_root=args.persisted_root,
                gamever=args.gamever,
                bindir=args.bindir,
                cutover_id=args.cutover_id,
            )
        else:
            result = [
                materialize_accepted_bin(
                    repo_root=args.repo_root,
                    persisted_root=args.persisted_root,
                    gamever=gamever,
                    bindir=args.bindir,
                )
                for gamever in _materialization_gamevers(args)
            ]
    except ReleaseWorkflowError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, default=str))
    return 0
