#!/usr/bin/env python3
"""Build, guard, and atomically publish immutable gamedata candidates."""

from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import subprocess
import tempfile
import uuid
from pathlib import Path

from analysis_config import validated_tag
from gamedata_contract import (
    GamedataContractError,
    analysis_config_sha256,
    discover_generator_modules,
    generator_contract_sha256,
    validate_gamedata_tree,
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
        "analysis_config_sha256": analysis_config_sha256(analysis_config),
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
    if analysis_config_sha256(config) != session["analysis_config_sha256"]:
        raise GamedataCandidateError("Analysis config changed after gamedata generation")
    modules = discover_generator_modules(session["modules_dir"])
    if generator_contract_sha256(modules) != session["generator_contract_sha256"]:
        raise GamedataCandidateError("Generator contract changed after gamedata generation")
    root = Path(session["candidate_root"]) / session["gamedata_path"]
    files, manifest_sha256 = validate_gamedata_tree(
        root,
        tag,
        modules,
        candidate_sha256=session["candidate_sha256"],
        analysis_config_sha256=session["analysis_config_sha256"],
        generator_contract_digest=session["generator_contract_sha256"],
    )
    if files != session["files"] or manifest_sha256 != session["gamedata_manifest_sha256"]:
        raise GamedataCandidateError("Gamedata candidate bytes changed after generation")
    return session


def verify_published_gamedata(*, session_path, repo_root, gamever, candidate, analysis_config):
    """Verify that the published ``gamedata/<gamever>`` tree matches the guarded candidate.

    Used by the release build to bind the working-tree gamedata to its immutable
    candidate session before staging. Reads the checked-out working tree and
    re-derives the generator contract from the build-time modules directory
    recorded in the session.
    """
    session = guard_candidate(session_path)
    tag = validated_tag(gamever)
    candidate = _file(candidate, "Symbol candidate")
    analysis_config = _file(analysis_config, "Analysis config")
    if session["gamever"] != tag or sha256_file(candidate) != session["candidate_sha256"]:
        raise GamedataCandidateError("Gamedata session does not match the release candidate")
    if analysis_config_sha256(analysis_config) != session["analysis_config_sha256"]:
        raise GamedataCandidateError("Gamedata session does not match the analysis config")
    root = Path(repo_root) / "gamedata" / tag
    if not root.is_dir():
        raise GamedataCandidateError(f"Published gamedata is missing: {root}")
    modules = discover_generator_modules(session["modules_dir"])
    files, manifest_sha256 = validate_gamedata_tree(
        root,
        tag,
        modules,
        candidate_sha256=session["candidate_sha256"],
        analysis_config_sha256=session["analysis_config_sha256"],
        generator_contract_digest=session["generator_contract_sha256"],
    )
    if files != session["files"] or manifest_sha256 != session["gamedata_manifest_sha256"]:
        raise GamedataCandidateError("Published gamedata differs from the guarded candidate")
    return {
        "gamedata_path": session["gamedata_path"],
        "gamedata_manifest_sha256": session["gamedata_manifest_sha256"],
        "generator_contract_sha256": session["generator_contract_sha256"],
    }


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
    incoming_files, incoming_manifest = validate_gamedata_tree(
        incoming,
        tag,
        modules,
        candidate_sha256=session["candidate_sha256"],
        analysis_config_sha256=session["analysis_config_sha256"],
        generator_contract_digest=session["generator_contract_sha256"],
    )
    if incoming_files != session["files"] or incoming_manifest != session["gamedata_manifest_sha256"]:
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
    published_files, published_manifest = validate_gamedata_tree(
        target,
        tag,
        modules,
        candidate_sha256=session["candidate_sha256"],
        analysis_config_sha256=session["analysis_config_sha256"],
        generator_contract_digest=session["generator_contract_sha256"],
    )
    if published_files != session["files"] or published_manifest != session["gamedata_manifest_sha256"]:
        raise GamedataCandidateError("Published gamedata failed final verification")
    return session


def _git(repo_root: Path, *args: str, env: dict[str, str] | None = None) -> bytes:
    result = subprocess.run(
        ["git", "-C", str(repo_root), *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        check=False,
    )
    if result.returncode != 0:
        raise GamedataCandidateError(
            f"git {' '.join(args)} failed: {result.stderr.decode('utf-8', errors='replace').strip()}"
        )
    return result.stdout


def _tree_inventory(repo_root: Path, ref: str, tag: str) -> list[dict]:
    prefix = f"gamedata/{validated_tag(tag)}/"
    raw = _git(repo_root, "ls-tree", "-r", "-z", ref, "--", prefix.removesuffix("/"))
    inventory = []
    for record in raw.split(b"\0"):
        if not record:
            continue
        metadata, separator, raw_path = record.partition(b"\t")
        parts = metadata.decode("ascii").split()
        path = raw_path.decode("utf-8")
        if (
            not separator
            or len(parts) != 3
            or parts[0] != "100644"
            or parts[1] != "blob"
            or not path.startswith(prefix)
        ):
            raise GamedataCandidateError(f"Tracked gamedata has an invalid Git tree entry: {path}")
        blob = _git(repo_root, "cat-file", "blob", parts[2])
        inventory.append({"path": path, "size": len(blob), "sha256": hashlib.sha256(blob).hexdigest()})
    return sorted(inventory, key=lambda item: item["path"])


def stage_candidate(*, session_path, repo_root):
    session = guard_candidate(session_path)
    repo = Path(repo_root).resolve()
    tag = session["gamever"]
    modules = discover_generator_modules(session["modules_dir"])
    target = repo / "gamedata" / tag
    files, manifest_sha256 = validate_gamedata_tree(
        target,
        tag,
        modules,
        candidate_sha256=session["candidate_sha256"],
        analysis_config_sha256=session["analysis_config_sha256"],
        generator_contract_digest=session["generator_contract_sha256"],
    )
    if files != session["files"] or manifest_sha256 != session["gamedata_manifest_sha256"]:
        raise GamedataCandidateError("Published gamedata does not match its candidate session")
    expected_paths = [item["path"] for item in session["files"]]
    stale_paths = sorted(set(item["path"] for item in _tree_inventory(repo, "HEAD", tag)) - set(expected_paths))

    def update_index(env=None):
        for path in stale_paths:
            _git(repo, "rm", "--cached", "--ignore-unmatch", "--", path, env=env)
        for path in expected_paths:
            _git(repo, "add", "-f", "--", path, env=env)

    with tempfile.TemporaryDirectory(prefix="gamedata-index-") as temporary:
        index_path = Path(temporary) / "index"
        index_env = dict(os.environ)
        index_env["GIT_INDEX_FILE"] = str(index_path)
        _git(repo, "read-tree", "HEAD", env=index_env)
        update_index(index_env)
        temporary_tree = _git(repo, "write-tree", env=index_env).decode("ascii").strip()
        if _tree_inventory(repo, temporary_tree, tag) != session["files"]:
            raise GamedataCandidateError("Temporary Git tree does not match gamedata candidate")
    update_index()
    staged_tree = _git(repo, "write-tree").decode("ascii").strip()
    if _tree_inventory(repo, staged_tree, tag) != session["files"]:
        raise GamedataCandidateError("Staged Git tree does not match gamedata candidate")
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
    stage = commands.add_parser("stage")
    stage.add_argument("-session", required=True)
    stage.add_argument("-repo-root", default=".")
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
        elif args.command == "publish":
            publish_candidate(session_path=args.session, output_dir=args.outputdir)
        elif args.command == "stage":
            stage_candidate(session_path=args.session, repo_root=args.repo_root)
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
