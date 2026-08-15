#!/usr/bin/env python3
"""Build, guard, and atomically publish immutable gamedata candidates."""

from __future__ import annotations

import argparse
import os
import shutil
import uuid
from pathlib import Path

from analysis_config import validated_tag
from gamedata_contract import (
    GamedataContractError,
    discover_generator_modules,
    gamedata_manifest_sha256,
    generator_contract_sha256,
    validate_output_tree,
)
from gamesymbol_store import SymbolStoreError
from release_workflow_lib.errors import ReleaseWorkflowError
from release_workflow_lib.hashing import load_json_object, sha256_file, write_canonical_json
from update_gamedata import generate_gamedata

SESSION_FIELDS = {
    "schema_version",
    "gamever",
    "build_id",
    "candidate_root",
    "snapshot_path",
    "analysis_config_path",
    "modules_dir",
    "gamedata_path",
    "candidate_sha256",
    "analysis_config_sha256",
    "generator_contract_sha256",
    "gamedata_manifest_sha256",
    "files",
}


class GamedataCandidateError(ValueError):
    pass


def _file(path, label):
    resolved = Path(path).resolve()
    if not resolved.is_file():
        raise GamedataCandidateError(f"{label} is missing: {resolved}")
    return resolved


def _load_session(path):
    session = load_json_object(path)
    if set(session) != SESSION_FIELDS or session.get("schema_version") != 1:
        raise GamedataCandidateError("Gamedata candidate session has unexpected fields or schema")
    return session


def build_candidate(
    *,
    gamever,
    build_id,
    snapshot,
    analysis_config,
    modules_dir,
    candidate_root,
    session_path,
):
    tag = validated_tag(gamever)
    snapshot = _file(snapshot, "Symbol candidate")
    analysis_config = _file(analysis_config, "Analysis config")
    modules_dir = Path(modules_dir).resolve()
    candidate_root = Path(candidate_root).resolve()
    version_root = candidate_root / "gamedata" / tag
    if version_root.exists() or Path(session_path).exists():
        raise GamedataCandidateError("Gamedata output and session must be new paths")
    result = generate_gamedata(
        gamever=tag,
        snapshot_path=snapshot,
        config_path=analysis_config,
        modules_dir=modules_dir,
        output_root=version_root,
    )
    session = {
        "schema_version": 1,
        "gamever": tag,
        "build_id": str(build_id),
        "candidate_root": str(candidate_root),
        "snapshot_path": str(snapshot),
        "analysis_config_path": str(analysis_config),
        "modules_dir": str(modules_dir),
        "gamedata_path": f"gamedata/{tag}",
        "candidate_sha256": sha256_file(snapshot),
        "analysis_config_sha256": sha256_file(analysis_config),
        "generator_contract_sha256": result["generator_contract_sha256"],
        "gamedata_manifest_sha256": result["gamedata_manifest_sha256"],
        "files": result["files"],
    }
    write_canonical_json(session_path, session)
    return session


def guard_candidate(session_path):
    session = _load_session(session_path)
    tag = validated_tag(session["gamever"])
    if session["gamedata_path"] != f"gamedata/{tag}":
        raise GamedataCandidateError("Gamedata path does not match its tag")
    snapshot = _file(session["snapshot_path"], "Symbol candidate")
    config = _file(session["analysis_config_path"], "Analysis config")
    if sha256_file(snapshot) != session["candidate_sha256"]:
        raise GamedataCandidateError("Symbol candidate changed after gamedata generation")
    if sha256_file(config) != session["analysis_config_sha256"]:
        raise GamedataCandidateError("Analysis config changed after gamedata generation")
    modules = discover_generator_modules(session["modules_dir"])
    if generator_contract_sha256(modules) != session["generator_contract_sha256"]:
        raise GamedataCandidateError("Generator contract changed after gamedata generation")
    root = Path(session["candidate_root"]) / session["gamedata_path"]
    files = validate_output_tree(root, tag, modules)
    if files != session["files"] or gamedata_manifest_sha256(files) != session["gamedata_manifest_sha256"]:
        raise GamedataCandidateError("Gamedata candidate bytes changed after generation")
    return session


def publish_candidate(*, session_path, output_dir):
    session = guard_candidate(session_path)
    tag = session["gamever"]
    source = Path(session["candidate_root"]) / session["gamedata_path"]
    target = Path(output_dir).resolve()
    if target.name != tag:
        raise GamedataCandidateError(f"Publish target must end with the exact tag: {target}")
    target.parent.mkdir(parents=True, exist_ok=True)
    incoming = target.parent / f".{tag}.incoming-{uuid.uuid4().hex}"
    backup = target.parent / f".{tag}.backup-{uuid.uuid4().hex}"
    shutil.copytree(source, incoming, copy_function=shutil.copy2)
    modules = discover_generator_modules(session["modules_dir"])
    incoming_files = validate_output_tree(incoming, tag, modules)
    if incoming_files != session["files"]:
        shutil.rmtree(incoming)
        raise GamedataCandidateError("Copied gamedata candidate failed verification")
    moved_old = False
    try:
        if target.exists():
            if not target.is_dir() or target.is_symlink():
                raise GamedataCandidateError(f"Unsafe gamedata publish target: {target}")
            os.replace(target, backup)
            moved_old = True
        os.replace(incoming, target)
    except (OSError, GamedataCandidateError) as exc:
        if moved_old and not target.exists() and backup.exists():
            os.replace(backup, target)
        if incoming.exists():
            shutil.rmtree(incoming)
        raise GamedataCandidateError(f"Atomic gamedata publication failed: {exc}") from exc
    if backup.exists():
        shutil.rmtree(backup)
    if validate_output_tree(target, tag, modules) != session["files"]:
        raise GamedataCandidateError("Published gamedata failed final verification")
    return session


def _parser():
    parser = argparse.ArgumentParser(description="Build, guard, and publish gamedata candidates")
    commands = parser.add_subparsers(dest="command", required=True)
    build = commands.add_parser("build")
    build.add_argument("-gamever", required=True)
    build.add_argument("-build-id", default="local")
    build.add_argument("-snapshot", required=True)
    build.add_argument("-configyaml", required=True)
    build.add_argument("-modulesdir", default="gamedata-generators")
    build.add_argument("-candidate-root", required=True)
    build.add_argument("-session", required=True)
    guard = commands.add_parser("guard")
    guard.add_argument("-session", required=True)
    publish = commands.add_parser("publish")
    publish.add_argument("-session", required=True)
    publish.add_argument("-outputdir", required=True)
    return parser


def main(argv=None):
    args = _parser().parse_args(argv)
    try:
        if args.command == "build":
            build_candidate(
                gamever=args.gamever,
                build_id=args.build_id,
                snapshot=args.snapshot,
                analysis_config=args.configyaml,
                modules_dir=args.modulesdir,
                candidate_root=args.candidate_root,
                session_path=args.session,
            )
        elif args.command == "guard":
            guard_candidate(args.session)
        else:
            publish_candidate(session_path=args.session, output_dir=args.outputdir)
    except (
        GamedataCandidateError,
        GamedataContractError,
        ReleaseWorkflowError,
        SymbolStoreError,
        OSError,
        ValueError,
    ) as exc:
        print(f"Error: {exc}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
