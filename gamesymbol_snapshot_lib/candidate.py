"""Immutable game-symbol candidate build, guard, compare, mark, and publish."""

from __future__ import annotations

import hashlib
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path

from gamesymbol_snapshot_lib.candidate_session import (
    VALIDATION_STEPS,
    CandidateContractError,
    absolute_path,
    atomic_json_write,
    ensure_real_path,
    file_identity,
    initial_manifest,
    load_manifest,
    update_session,
)
from gamesymbol_snapshot_lib.codec import (
    canonical_snapshot_bytes,
    parse_snapshot_bytes,
    snapshot_config_digest_version,
)
from gamesymbol_snapshot_lib.diff import format_snapshot_mismatch
from gamesymbol_snapshot_lib.errors import SnapshotMismatchError, SnapshotSchemaError
from gamesymbol_snapshot_lib.operations import pack_snapshot
from gamesymbol_snapshot_lib.paths import is_reparse_point
from gamesymbol_store import CandidateChangedError, SnapshotSymbolStore


class CandidatePublicationError(Exception):
    pass


@dataclass(frozen=True)
class CandidateInfo:
    path: str
    candidate_sha256: str
    game_version: str
    snapshot_schema_version: int
    config_digest_version: int
    config_sha256: str
    file_count: int


@dataclass(frozen=True)
class SnapshotDiff:
    actual_sha256: str
    expected_sha256: str
    equal: bool


@dataclass(frozen=True)
class PublishedInfo:
    path: str
    candidate_sha256: str
    byte_count: int


def _digest(raw: bytes) -> str:
    return f"sha256:{hashlib.sha256(raw).hexdigest()}"


def _candidate_info(path: Path) -> CandidateInfo:
    try:
        raw = path.read_bytes()
        document = parse_snapshot_bytes(raw)
    except (OSError, SnapshotSchemaError) as exc:
        raise CandidateContractError(f"Candidate snapshot is invalid: {exc}") from exc
    if canonical_snapshot_bytes(document) != raw:
        raise CandidateContractError(f"Candidate snapshot is not canonical: {path}")
    return CandidateInfo(
        str(path),
        _digest(raw),
        document["game_version"],
        document["schema_version"],
        snapshot_config_digest_version(document),
        document["config_sha256"],
        document["file_count"],
    )


def build_candidate_snapshot(
    *, game_version, bin_root, config_path, output_path, session_path, last_publish_time=None
) -> CandidateInfo:
    output, session = absolute_path(output_path), absolute_path(session_path)
    tracked_root = absolute_path(Path.cwd() / "gamesymbols")
    if output == tracked_root or tracked_root in output.parents:
        raise CandidateContractError("Candidate output must not use the tracked gamesymbols namespace")
    if output.parent != session.parent or output.exists() or session.exists():
        raise CandidateContractError("Candidate and session must be new paths in one staging directory")
    output.parent.mkdir(parents=True, exist_ok=True)
    ensure_real_path(output)
    ensure_real_path(session)
    try:
        pack_snapshot(
            game_version,
            bin_root,
            config_path,
            output,
            last_publish_time=last_publish_time,
            strict=True,
        )
        store = SnapshotSymbolStore.open(output, expected_game_version=str(game_version), config_path=config_path)
        info = _candidate_info(output)
        if store.candidate_sha256 != info.candidate_sha256:
            raise CandidateChangedError("Candidate hash changed during reopen validation")
        atomic_json_write(session, initial_manifest(info, output))
        return info
    except Exception:
        if output.exists() and not session.exists():
            output.unlink()
        raise


def guard_candidate(*, candidate_path, session_path) -> CandidateInfo:
    candidate = absolute_path(candidate_path)
    ensure_real_path(candidate, require_file=True)
    _session, manifest = load_manifest(session_path)
    if manifest["candidate_path"] != str(candidate):
        raise CandidateChangedError("Candidate path does not match session")
    try:
        info = _candidate_info(candidate)
    except CandidateContractError as exc:
        raise CandidateChangedError(str(exc)) from exc
    for field in (
        "candidate_sha256",
        "game_version",
        "snapshot_schema_version",
        "config_digest_version",
        "config_sha256",
        "file_count",
    ):
        if manifest[field] != getattr(info, field):
            raise CandidateChangedError(f"Candidate {field} changed after build")
    if manifest["file_identity"] != file_identity(candidate):
        raise CandidateChangedError("Candidate file identity changed after build")
    return info


def compare_snapshots(*, actual_path, expected_path, config_path, expected_game_version, session_path=None):
    if session_path:
        guard_candidate(candidate_path=actual_path, session_path=session_path)
    actual = SnapshotSymbolStore.open(
        actual_path, expected_game_version=str(expected_game_version), config_path=config_path
    )
    expected = SnapshotSymbolStore.open(
        expected_path, expected_game_version=str(expected_game_version), config_path=config_path
    )
    actual_document = parse_snapshot_bytes(Path(actual_path).read_bytes())
    expected_document = parse_snapshot_bytes(Path(expected_path).read_bytes())
    comparable_actual, comparable_expected = dict(actual_document), dict(expected_document)
    comparable_actual.pop("last_publish_time", None)
    comparable_expected.pop("last_publish_time", None)
    if comparable_actual != comparable_expected:
        raise SnapshotMismatchError(format_snapshot_mismatch(comparable_expected, comparable_actual))
    if session_path:
        session, manifest = load_manifest(session_path)
        manifest["completed_steps"]["expected_compare"] = True
        update_session(session, manifest, state="expected_matched")
    return SnapshotDiff(actual.candidate_sha256, expected.candidate_sha256, True)


def complete_candidate_step(*, candidate_path, session_path, step: str):
    if step not in VALIDATION_STEPS:
        raise CandidateContractError(f"Unsupported candidate validation step: {step}")
    info = guard_candidate(candidate_path=candidate_path, session_path=session_path)
    session, manifest = load_manifest(session_path)
    manifest["completed_steps"][step] = True
    update_session(session, manifest, state="validated")
    return info


def _atomic_publish(destination: Path, raw: bytes, digest: str) -> None:
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(
            dir=destination.parent, prefix=f".{destination.name}.", delete=False
        ) as handle:
            temporary = Path(handle.name)
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        if _digest(temporary.read_bytes()) != digest:
            raise CandidatePublicationError("Temporary publication hash mismatch")
        os.replace(temporary, destination)
    except OSError as exc:
        raise CandidatePublicationError(f"Unable to publish candidate: {exc}") from exc
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()


def publish_candidate(*, candidate_path, session_path, destination):
    info = guard_candidate(candidate_path=candidate_path, session_path=session_path)
    session, manifest = load_manifest(session_path)
    if manifest["state"] != "validated" or not manifest["completed_steps"]["gamedata"]:
        raise CandidateContractError("Candidate requires guarded gamedata before publication")
    target = absolute_path(destination)
    tracked_root = absolute_path(Path.cwd() / "gamesymbols")
    if target.parent != tracked_root or target.name != f"{info.game_version}.yaml":
        raise CandidateContractError(f"Published snapshot must be gamesymbols/{info.game_version}.yaml")
    target.parent.mkdir(parents=True, exist_ok=True)
    ensure_real_path(target)
    if target.exists() and (is_reparse_point(target) or not target.is_file()):
        raise CandidateContractError(f"Unsafe publication destination: {target}")
    raw = Path(info.path).read_bytes()
    _atomic_publish(target, raw, info.candidate_sha256)
    if _digest(target.read_bytes()) != info.candidate_sha256:
        raise CandidatePublicationError("Published snapshot hash mismatch")
    update_session(session, manifest, state="published")
    return PublishedInfo(str(target), info.candidate_sha256, len(raw))
