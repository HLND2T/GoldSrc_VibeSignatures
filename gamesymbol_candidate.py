#!/usr/bin/env python3
"""CLI for immutable game-symbol candidates."""

from __future__ import annotations

import argparse

from gamesymbol_snapshot_lib.candidate import (
    build_candidate_snapshot,
    complete_candidate_step,
    guard_candidate,
    publish_candidate,
)
from gamesymbol_snapshot_lib.candidate_session import CandidateContractError
from gamesymbol_snapshot_lib.errors import SnapshotError
from gamesymbol_store import SymbolStoreError


def _parser():
    parser = argparse.ArgumentParser(description="Build, compare, guard, mark, and publish symbol candidates")
    commands = parser.add_subparsers(dest="command", required=True)
    build = commands.add_parser("build")
    build.add_argument("-gamever", required=True)
    build.add_argument("-bindir", default="bin")
    build.add_argument("-artifactdir", default="bin_artifacts")
    build.add_argument("-configyaml", default=None)
    build.add_argument("-output", required=True)
    build.add_argument("-session", required=True)
    build.add_argument("-last-publish-time", default=None)
    for name in ("guard", "mark", "publish"):
        command = commands.add_parser(name)
        command.add_argument("-candidate", required=True)
        command.add_argument("-session", required=True)
        if name == "mark":
            command.add_argument("-step", choices=["gamedata", "json"], required=True)
            command.add_argument("-gamedata-session")
            command.add_argument("-json-session")
        if name == "publish":
            command.add_argument("-destination", required=True)
    return parser


def main(argv=None):
    args = _parser().parse_args(argv)
    try:
        if args.command == "build":
            build_candidate_snapshot(
                game_version=args.gamever,
                bin_root=args.bindir,
                artifact_root=args.artifactdir,
                config_path=args.configyaml,
                output_path=args.output,
                session_path=args.session,
                last_publish_time=args.last_publish_time,
            )
        elif args.command == "guard":
            guard_candidate(candidate_path=args.candidate, session_path=args.session)
        elif args.command == "mark":
            info = guard_candidate(candidate_path=args.candidate, session_path=args.session)
            if args.step == "gamedata":
                from gamedata_candidate import guard_candidate as guard_gamedata_candidate

                if not args.gamedata_session:
                    raise CandidateContractError("mark -step gamedata requires -gamedata-session")
                gamedata_session = guard_gamedata_candidate(args.gamedata_session)
                if gamedata_session["gamever"] != info.game_version or gamedata_session[
                    "candidate_sha256"
                ] != info.candidate_sha256.removeprefix("sha256:"):
                    raise CandidateContractError("Gamedata session does not guard this game-symbol candidate")
            else:
                from gamesymbols_json import guard_dataset_session

                if not args.json_session:
                    raise CandidateContractError("mark -step json requires -json-session")
                json_session = guard_dataset_session(args.json_session)
                if json_session["gamever"] != info.game_version or json_session[
                    "snapshot_sha256"
                ] != info.candidate_sha256.removeprefix("sha256:"):
                    raise CandidateContractError("JSON session does not guard this game-symbol candidate")
            complete_candidate_step(candidate_path=args.candidate, session_path=args.session, step=args.step)
        else:
            publish_candidate(candidate_path=args.candidate, session_path=args.session, destination=args.destination)
    except (CandidateContractError, SnapshotError, SymbolStoreError, OSError, ValueError) as exc:
        print(f"Error: {exc}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
