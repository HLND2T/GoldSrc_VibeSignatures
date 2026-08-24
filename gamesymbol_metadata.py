#!/usr/bin/env python3
"""Generate, verify, and compare immutable game-symbol metadata companions."""

from __future__ import annotations

import argparse

from gamesymbol_snapshot_lib.metadata import MetadataContractError, compare_metadata, verify_metadata, write_metadata


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("generate", "verify"):
        command = commands.add_parser(name)
        command.add_argument("-snapshot", required=True)
        command.add_argument("-configyaml", required=True)
        command.add_argument("-gamever", required=True)
        command.add_argument("-metadata", required=True)
    compare = commands.add_parser("compare")
    compare.add_argument("-snapshot", required=True)
    compare.add_argument("-configyaml", required=True)
    compare.add_argument("-gamever", required=True)
    compare.add_argument("-actual", required=True)
    compare.add_argument("-expected", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "generate":
            write_metadata(
                snapshot_path=args.snapshot,
                config_path=args.configyaml,
                game_version=args.gamever,
                output_path=args.metadata,
            )
        elif args.command == "verify":
            verify_metadata(
                metadata_path=args.metadata,
                snapshot_path=args.snapshot,
                config_path=args.configyaml,
                game_version=args.gamever,
            )
        else:
            compare_metadata(
                actual_path=args.actual,
                expected_path=args.expected,
                snapshot_path=args.snapshot,
                config_path=args.configyaml,
                game_version=args.gamever,
            )
    except (MetadataContractError, OSError, ValueError) as exc:
        print(f"Error: {exc}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
