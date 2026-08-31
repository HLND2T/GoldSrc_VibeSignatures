#!/usr/bin/env python3
"""CLI for canonical game-symbol snapshot restore and verification."""

from __future__ import annotations

import argparse

from gamesymbol_snapshot_lib.errors import SnapshotError, SnapshotUntrustedError
from gamesymbol_snapshot_lib.operations import check_snapshot_contract, restore_snapshot, verify_snapshot


def _parser():
    parser = argparse.ArgumentParser(description="Explicitly restore or verify canonical game-symbol snapshots")
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("restore-legacy", "verify", "check-contract"):
        command = commands.add_parser(name)
        command.add_argument("-gamever", required=True)
        command.add_argument("-bindir", default="bin")
        command.add_argument("-artifactdir", default="bin_artifacts")
        command.add_argument("-config", default=None)
        command.add_argument("-snapshot", required=True)
        if name == "restore-legacy":
            command.add_argument("-replace", action="store_true")
    return parser


def main(argv=None):
    args = _parser().parse_args(argv)
    try:
        kwargs = {
            "game_version": args.gamever,
            "bindir": args.bindir,
            "artifactdir": args.artifactdir,
            "config_path": args.config,
            "snapshot_path": args.snapshot,
        }
        if args.command == "restore-legacy":
            restore_snapshot(**kwargs, replace=args.replace)
        elif args.command == "verify":
            verify_snapshot(**kwargs)
        else:
            check_snapshot_contract(**kwargs)
    except SnapshotUntrustedError as exc:
        print(f"Error [{exc.reason}]: {exc}")
        return 3
    except SnapshotError as exc:
        print(f"Error: {exc}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
