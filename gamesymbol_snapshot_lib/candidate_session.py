"""Immutable candidate session manifest."""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import asdict
from pathlib import Path

from gamesymbol_snapshot_lib.paths import is_reparse_point

SESSION_SCHEMA_VERSION = 2
VALIDATION_STEPS = ("gamedata",)


class CandidateContractError(Exception):
    pass


def absolute_path(path) -> Path:
    return Path(os.path.abspath(path))


def ensure_real_path(path: Path, *, require_file=False):
    candidates = (path, *path.parents) if require_file else (path.parent, *path.parent.parents)
    for candidate in candidates:
        if candidate.exists() and is_reparse_point(candidate):
            raise CandidateContractError(f"Candidate path traverses a link/reparse point: {candidate}")
    if require_file and not path.is_file():
        raise CandidateContractError(f"Candidate file does not exist: {path}")


def file_identity(path: Path) -> dict[str, int]:
    stat = path.stat()
    return {"device": int(stat.st_dev), "inode": int(stat.st_ino), "size": stat.st_size, "mtime_ns": stat.st_mtime_ns}


def atomic_json_write(path: Path, payload: dict) -> None:
    data = (json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, prefix=f".{path.name}.", delete=False) as handle:
            temporary = Path(handle.name)
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()


def initial_manifest(info, output: Path, metadata_output: Path) -> dict:
    return {
        "schema_version": SESSION_SCHEMA_VERSION,
        **asdict(info),
        "candidate_path": str(output),
        "file_identity": file_identity(output),
        "metadata_file_identity": file_identity(metadata_output),
        "state": "candidate_ready",
        "completed_steps": {"analysis": True, "pack": True, "gamedata": False},
    }


def load_manifest(session_path):
    session = absolute_path(session_path)
    ensure_real_path(session, require_file=True)
    try:
        manifest = json.loads(session.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CandidateContractError(f"Unable to read candidate session {session}: {exc}") from exc
    required = {
        "schema_version",
        "path",
        "candidate_sha256",
        "game_version",
        "snapshot_schema_version",
        "config_digest_version",
        "config_sha256",
        "file_count",
        "metadata_path",
        "metadata_sha256",
        "metadata_snapshot_sha256",
        "candidate_path",
        "file_identity",
        "metadata_file_identity",
        "state",
        "completed_steps",
    }
    if (
        not isinstance(manifest, dict)
        or set(manifest) != required
        or manifest.get("schema_version") != SESSION_SCHEMA_VERSION
    ):
        raise CandidateContractError(f"Unsupported or malformed candidate session: {session}")
    if set(manifest["completed_steps"]) != {"analysis", "pack", "gamedata"}:
        raise CandidateContractError("Candidate session has malformed completed steps")
    return session, manifest


def update_session(session: Path, manifest: dict, *, state=None):
    if state is not None:
        manifest["state"] = state
    atomic_json_write(session, manifest)
