"""Immutable game-symbol candidate build, guard, compare, mark, and publish."""

from __future__ import annotations

import hashlib
import json
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
from gamesymbol_snapshot_lib.errors import SnapshotSchemaError
from gamesymbol_snapshot_lib.metadata import (
    MetadataContractError,
    companion_path,
    parse_metadata_bytes,
    raw_sha256,
    write_metadata,
)
from gamesymbol_snapshot_lib.operations import pack_snapshot
from gamesymbol_snapshot_lib.paths import is_reparse_point, metadata_filename, snapshot_tag_from_filename
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
    metadata_path: str
    metadata_sha256: str
    metadata_snapshot_sha256: str


@dataclass(frozen=True)
class PublishedInfo:
    path: str
    candidate_sha256: str
    byte_count: int
    metadata_path: str
    metadata_sha256: str
    metadata_byte_count: int


def _digest(raw: bytes) -> str:
    return f"sha256:{hashlib.sha256(raw).hexdigest()}"


def _candidate_info(path: Path, metadata_path: Path) -> CandidateInfo:
    try:
        raw = path.read_bytes()
        document = parse_snapshot_bytes(raw)
    except (OSError, SnapshotSchemaError) as exc:
        raise CandidateContractError(f"Candidate snapshot is invalid: {exc}") from exc
    if canonical_snapshot_bytes(document) != raw:
        raise CandidateContractError(f"Candidate snapshot is not canonical: {path}")
    try:
        metadata_raw = metadata_path.read_bytes()
        metadata = parse_metadata_bytes(
            metadata_raw,
            expected_game_version=document["game_version"],
            snapshot_bytes=raw,
        )
    except (OSError, MetadataContractError) as exc:
        raise CandidateContractError(f"Candidate metadata is invalid: {exc}") from exc
    if metadata["config_digest_version"] != snapshot_config_digest_version(document):
        raise CandidateContractError("Candidate metadata config digest version mismatch")
    if metadata["config_sha256"] != document["config_sha256"].removeprefix("sha256:"):
        raise CandidateContractError("Candidate metadata config digest mismatch")
    return CandidateInfo(
        str(path),
        _digest(raw),
        document["game_version"],
        document["schema_version"],
        snapshot_config_digest_version(document),
        document["config_sha256"],
        document["file_count"],
        str(metadata_path),
        f"sha256:{raw_sha256(metadata_raw)}",
        f"sha256:{metadata['snapshot_sha256']}",
    )


def build_candidate_snapshot(
    *,
    game_version,
    bin_root,
    artifact_root,
    config_path,
    output_path,
    session_path,
    metadata_output_path=None,
    last_publish_time=None,
) -> CandidateInfo:
    output, session = absolute_path(output_path), absolute_path(session_path)
    if snapshot_tag_from_filename(output.name) != str(game_version):
        raise CandidateContractError(f"Candidate snapshot must be named {game_version}.yaml")
    metadata_output = absolute_path(metadata_output_path or companion_path(output))
    tracked_root = absolute_path(Path.cwd() / "gamesymbols")
    if output == tracked_root or tracked_root in output.parents:
        raise CandidateContractError("Candidate output must not use the tracked gamesymbols namespace")
    if output.parent != session.parent or metadata_output.parent != output.parent:
        raise CandidateContractError("Candidate, metadata, and session must share one staging directory")
    if output.exists() or metadata_output.exists() or session.exists():
        raise CandidateContractError("Candidate, metadata, and session must be new staging paths")
    output.parent.mkdir(parents=True, exist_ok=True)
    ensure_real_path(output)
    ensure_real_path(metadata_output)
    ensure_real_path(session)
    try:
        tracked_snapshot = tracked_root / f"{game_version}.yaml"
        if last_publish_time is None and tracked_snapshot.is_file():
            tracked_document = parse_snapshot_bytes(tracked_snapshot.read_bytes(), str(game_version))
            last_publish_time = tracked_document.get("last_publish_time")
        pack_snapshot(
            game_version,
            bin_root,
            config_path,
            output,
            artifactdir=artifact_root,
            last_publish_time=last_publish_time,
            strict=True,
        )
        write_metadata(
            snapshot_path=output,
            config_path=config_path,
            game_version=str(game_version),
            output_path=metadata_output,
        )
        store = SnapshotSymbolStore.open(output, expected_game_version=str(game_version), config_path=config_path)
        info = _candidate_info(output, metadata_output)
        if store.candidate_sha256 != info.candidate_sha256:
            raise CandidateChangedError("Candidate hash changed during reopen validation")
        atomic_json_write(session, initial_manifest(info, output, metadata_output))
        return info
    except Exception:
        if not session.exists():
            for path in (output, metadata_output):
                if path.exists():
                    path.unlink()
        raise


def guard_candidate(*, candidate_path, session_path) -> CandidateInfo:
    candidate = absolute_path(candidate_path)
    ensure_real_path(candidate, require_file=True)
    _session, manifest = load_manifest(session_path)
    if manifest["candidate_path"] != str(candidate):
        raise CandidateChangedError("Candidate path does not match session")
    metadata = absolute_path(manifest["metadata_path"])
    ensure_real_path(metadata, require_file=True)
    try:
        info = _candidate_info(candidate, metadata)
    except CandidateContractError as exc:
        raise CandidateChangedError(str(exc)) from exc
    for field in (
        "candidate_sha256",
        "game_version",
        "snapshot_schema_version",
        "config_digest_version",
        "config_sha256",
        "file_count",
        "metadata_path",
        "metadata_sha256",
        "metadata_snapshot_sha256",
    ):
        if manifest[field] != getattr(info, field):
            raise CandidateChangedError(f"Candidate {field} changed after build")
    if manifest["file_identity"] != file_identity(candidate):
        raise CandidateChangedError("Candidate file identity changed after build")
    if manifest["metadata_file_identity"] != file_identity(metadata):
        raise CandidateChangedError("Candidate metadata file identity changed after build")
    return info


def complete_candidate_step(*, candidate_path, session_path, step: str):
    if step not in VALIDATION_STEPS:
        raise CandidateContractError(f"Unsupported candidate validation step: {step}")
    info = guard_candidate(candidate_path=candidate_path, session_path=session_path)
    session, manifest = load_manifest(session_path)
    manifest["completed_steps"][step] = True
    update_session(session, manifest, state="validated")
    return info


def _temporary_bytes(destination: Path, raw: bytes, prefix: str) -> Path:
    with tempfile.NamedTemporaryFile(dir=destination.parent, prefix=prefix, delete=False) as handle:
        path = Path(handle.name)
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())
    return path


def _journal_cleanup(journal: Path, document: dict) -> None:
    for entry in document.get("entries", []):
        for key in ("new_temporary", "old_backup"):
            value = entry.get(key)
            if value and Path(value).exists():
                Path(value).unlink()
    if journal.exists():
        journal.unlink()


def _recover_publication(journal: Path, expected_targets: tuple[Path, Path]) -> None:
    if not journal.exists():
        return
    try:
        document = json.loads(journal.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CandidatePublicationError(f"Unable to recover publication journal: {exc}") from exc
    if (
        not isinstance(document, dict)
        or document.get("schema_version") != 1
        or not isinstance(document.get("entries"), list)
    ):
        raise CandidatePublicationError("Malformed publication journal")
    if tuple(entry.get("target") for entry in document["entries"]) != tuple(str(path) for path in expected_targets):
        raise CandidatePublicationError("Publication journal targets do not match the requested pair")
    if document.get("state") == "committed":
        for entry in document["entries"]:
            target = Path(entry["target"])
            if not target.is_file() or _digest(target.read_bytes()) != entry["new_sha256"]:
                raise CandidatePublicationError("Committed publication journal does not match targets")
        _journal_cleanup(journal, document)
        return
    for entry in reversed(document["entries"]):
        target = Path(entry["target"])
        backup_value = entry.get("old_backup")
        if entry["old_exists"]:
            backup = Path(backup_value)
            if not backup.is_file() or _digest(backup.read_bytes()) != entry["old_sha256"]:
                raise CandidatePublicationError("Publication rollback backup is missing or changed")
            os.replace(backup, target)
        elif target.exists():
            target.unlink()
    _journal_cleanup(journal, document)


def _publish_pair(
    *, target: Path, target_metadata: Path, snapshot_raw: bytes, metadata_raw: bytes, info: CandidateInfo
) -> None:
    journal = target.parent / f".{info.game_version}.publish-journal.json"
    _recover_publication(journal, (target, target_metadata))
    entries = []
    for destination, raw, digest in (
        (target, snapshot_raw, info.candidate_sha256),
        (target_metadata, metadata_raw, info.metadata_sha256),
    ):
        old_exists = destination.is_file()
        old_raw = destination.read_bytes() if old_exists else b""
        backup = _temporary_bytes(destination, old_raw, f".{destination.name}.old-") if old_exists else None
        temporary = _temporary_bytes(destination, raw, f".{destination.name}.new-")
        if _digest(temporary.read_bytes()) != digest:
            raise CandidatePublicationError("Temporary publication hash mismatch")
        entries.append(
            {
                "target": str(destination),
                "old_exists": old_exists,
                "old_sha256": _digest(old_raw) if old_exists else None,
                "old_backup": str(backup) if backup is not None else None,
                "new_sha256": digest,
                "new_temporary": str(temporary),
            }
        )
    document = {"schema_version": 1, "state": "prepared", "entries": entries}
    atomic_json_write(journal, document)
    try:
        os.replace(entries[0]["new_temporary"], target)
        document["state"] = "snapshot_replaced"
        atomic_json_write(journal, document)
        os.replace(entries[1]["new_temporary"], target_metadata)
        document["state"] = "metadata_replaced"
        atomic_json_write(journal, document)
        if (
            _digest(target.read_bytes()) != info.candidate_sha256
            or _digest(target_metadata.read_bytes()) != info.metadata_sha256
        ):
            raise CandidatePublicationError("Published snapshot/metadata pair hash mismatch")
        document["state"] = "committed"
        atomic_json_write(journal, document)
        _journal_cleanup(journal, document)
    except (OSError, CandidatePublicationError) as exc:
        raise CandidatePublicationError(f"Unable to publish candidate pair: {exc}") from exc


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
    target_metadata = target.with_name(metadata_filename(info.game_version))
    ensure_real_path(target)
    ensure_real_path(target_metadata)
    for publication_target in (target, target_metadata):
        if publication_target.exists() and (is_reparse_point(publication_target) or not publication_target.is_file()):
            raise CandidateContractError(f"Unsafe publication destination: {publication_target}")
    raw = Path(info.path).read_bytes()
    metadata_raw = Path(info.metadata_path).read_bytes()
    _publish_pair(
        target=target,
        target_metadata=target_metadata,
        snapshot_raw=raw,
        metadata_raw=metadata_raw,
        info=info,
    )
    update_session(session, manifest, state="published")
    return PublishedInfo(
        str(target),
        info.candidate_sha256,
        len(raw),
        str(target_metadata),
        info.metadata_sha256,
        len(metadata_raw),
    )
