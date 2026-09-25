"""Persistent selection pins. Every filesystem operation requires the caller's tag lock.

Preparing pins protect entries before the final selection exists. Sealing binds them to
its canonical digest; only a completely restored selection releases its own pins.
Generation payloads and their schema remain immutable and independent of this protocol.
"""

from __future__ import annotations

import json
import re
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from ida_database_paths import is_reparse_point
from idb_cache_locks import IdbCacheError
from release_workflow_lib.hashing import canonical_json_bytes, write_canonical_json

CACHE_DIRECTORY_NAME = "idb-cache-v2"
LEASE_SCHEMA_VERSION = 1
# GitHub's whole-workflow limit is 35 days, including approval and queue time.
# A fresh pin also covers the rest of Prepare; an extra day bounds clock/cleanup slack.
LEASE_LIFETIME = timedelta(days=36)
CLOCK_SKEW_ALLOWANCE = timedelta(hours=1)
LEASE_KEYS = {"lease_id", "repository", "run_id", "attempt", "created_at", "expires_at"}
RECORD_KEYS = {"schema_version", "tag", "lease", "selection_sha256", "references"}
REFERENCE_KEYS = {"platform", "cache_key", "generation", "manifest_sha256"}
COMPONENT_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,159}", re.ASCII)
DIGEST_RE = re.compile(r"[0-9a-f]{64}", re.ASCII)
LEASE_ID_RE = re.compile(r"[0-9a-f]{32}", re.ASCII)
TEMPORARY_RE = re.compile(r"\.[0-9a-f]{32}\.json\.[0-9a-f]{32}\.tmp", re.ASCII)
TIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
RECOVERY_HINT = "Re-run the full workflow, including the warm IDB producer, to obtain a new selection."


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _time(value: object) -> datetime:
    try:
        parsed = datetime.strptime(value, TIME_FORMAT).replace(tzinfo=timezone.utc)
        if parsed.strftime(TIME_FORMAT) != value:
            raise ValueError("noncanonical time")
        return parsed
    except (TypeError, ValueError) as exc:
        raise IdbCacheError("Lease timestamps must use UTC second precision") from exc


def _matches(pattern, value: object, label: str) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise IdbCacheError(f"Invalid lease {label}")
    return value


def validate_lease_descriptor(lease: object) -> dict:
    """Validate immutable evidence without applying the live cache retention policy."""
    if not isinstance(lease, dict) or set(lease) != LEASE_KEYS:
        raise IdbCacheError("Selection lease has unexpected fields")
    _matches(LEASE_ID_RE, lease["lease_id"], "ID")
    _matches(COMPONENT_RE, lease["run_id"], "run ID")
    repository = lease["repository"]
    if not isinstance(repository, str) or not (
        repository == "local"
        or len(repository.split("/")) == 2
        and all(COMPONENT_RE.fullmatch(part) for part in repository.split("/"))
    ):
        raise IdbCacheError("Invalid lease repository")
    if type(lease["attempt"]) is not int or lease["attempt"] < 1:
        raise IdbCacheError("Lease attempt must be a positive integer")
    if _time(lease["expires_at"]) <= _time(lease["created_at"]):
        raise IdbCacheError("Invalid lease lifetime")
    return lease


def validate_lease(lease: object) -> dict:
    lease = validate_lease_descriptor(lease)
    if _time(lease["expires_at"]) - _time(lease["created_at"]) != LEASE_LIFETIME:
        raise IdbCacheError("Invalid lease lifetime")
    if _time(lease["created_at"]) > utc_now() + CLOCK_SKEW_ALLOWANCE:
        raise IdbCacheError("Lease creation time is in the future; check runner clocks before pruning")
    return lease


def new_lease(*, repository: str, run_id: str, attempt: int) -> dict:
    created = utc_now().replace(microsecond=0)
    return validate_lease(
        {
            "lease_id": uuid.uuid4().hex,
            "repository": repository,
            "run_id": run_id,
            "attempt": attempt,
            "created_at": created.strftime(TIME_FORMAT),
            "expires_at": (created + LEASE_LIFETIME).strftime(TIME_FORMAT),
        }
    )


def _require_live(lease: dict) -> None:
    if utc_now() >= _time(lease["expires_at"]):
        raise IdbCacheError(f"Selection lease expired: {lease['lease_id']}. {RECOVERY_HINT}")


def lease_reference(entry: dict) -> dict:
    reference = {key: entry[key] for key in REFERENCE_KEYS}
    _validate_references([reference])
    return reference


def _validate_references(references: object) -> None:
    if not isinstance(references, list) or not references:
        raise IdbCacheError("Lease must protect at least one generation")
    platforms = []
    for reference in references:
        if not isinstance(reference, dict) or set(reference) != REFERENCE_KEYS:
            raise IdbCacheError("Lease generation reference has unexpected fields")
        if reference["platform"] not in ("windows", "linux"):
            raise IdbCacheError("Invalid lease platform")
        _matches(COMPONENT_RE, reference["generation"], "generation")
        for field in ("cache_key", "manifest_sha256"):
            _matches(DIGEST_RE, reference[field], field)
        platforms.append(reference["platform"])
    if platforms != sorted(set(platforms)):
        raise IdbCacheError("Lease references must have unique, sorted platforms")


def _plain(path: Path, *, directory: bool) -> bool:
    try:
        reparse = is_reparse_point(path)
    except FileNotFoundError:
        return False
    if reparse or not (path.is_dir() if directory else path.is_file()):
        raise IdbCacheError(f"Lease path must be a plain {'directory' if directory else 'file'}: {path}")
    return True


def _directory(tag_root: Path, *, create: bool = False) -> Path:
    # tag_root is obtained through idb_cache._tag_root, which validates its ancestors.
    directory = tag_root / "leases"
    if not _plain(directory, directory=True) and create:
        directory.mkdir()
    return directory


def _path(tag_root: Path, lease: dict, *, create: bool = False) -> Path:
    validate_lease(lease)
    return _directory(tag_root, create=create) / f"{lease['lease_id']}.json"


def _read(path: Path, tag: str) -> dict:
    if not _plain(path, directory=False):
        raise IdbCacheError(f"Selection lease is missing or released: {path.name}. {RECOVERY_HINT}")
    try:
        raw = path.read_bytes()
        record = json.loads(raw)
        canonical = canonical_json_bytes(record)
    except (OSError, ValueError) as exc:
        raise IdbCacheError(f"Unable to read selection lease {path}: {exc}") from exc
    if (
        not isinstance(record, dict)
        or set(record) != RECORD_KEYS
        or type(record["schema_version"]) is not int
        or record["schema_version"] != LEASE_SCHEMA_VERSION
        or record["tag"] != tag
        or canonical != raw
    ):
        raise IdbCacheError(f"Invalid canonical lease record: {path}")
    lease = validate_lease(record["lease"])
    if path.name != f"{lease['lease_id']}.json":
        raise IdbCacheError("Lease filename does not bind its ID")
    _validate_references(record["references"])
    if record["selection_sha256"] is not None:
        _matches(DIGEST_RE, record["selection_sha256"], "selection digest")
    return record


def _log(event: str, record: dict) -> None:
    lease = record["lease"]
    print(
        f"IDB cache lease {event}: tag={record['tag']}; lease_id={lease['lease_id']}; "
        f"owner={lease['repository']}/{lease['run_id']}/{lease['attempt']}; "
        f"expires_at={lease['expires_at']}; selection_sha256={record['selection_sha256']}; "
        f"generations={','.join(ref['generation'] for ref in record['references'])}",
        flush=True,
    )


def pin_generation(*, tag_root: Path, lease: dict, reference: dict) -> None:
    path = _path(tag_root, lease, create=True)
    _require_live(lease)
    _validate_references([reference])
    if _plain(path, directory=False):
        record = _read(path, tag_root.name)
        if record["lease"] != lease or record["selection_sha256"] is not None:
            raise IdbCacheError("Cannot change a sealed or differently owned lease")
        if reference in record["references"]:
            return
        references = sorted([*record["references"], reference], key=lambda ref: ref["platform"])
        _validate_references(references)
        record["references"] = references
    else:
        record = {
            "schema_version": LEASE_SCHEMA_VERSION,
            "tag": tag_root.name,
            "lease": lease,
            "selection_sha256": None,
            "references": [reference],
        }
    write_canonical_json(path, record)
    _log("pinned", record)


def seal_lease(*, tag_root: Path, lease: dict, selection_sha256: str, references: list[dict]) -> None:
    path = _path(tag_root, lease)
    _require_live(lease)
    _matches(DIGEST_RE, selection_sha256, "selection digest")
    record = _read(path, tag_root.name)
    if record["lease"] != lease or record["references"] != references:
        raise IdbCacheError("Selection does not match its preparing lease")
    if record["selection_sha256"] not in (None, selection_sha256):
        raise IdbCacheError("Lease is already bound to a different selection")
    record["selection_sha256"] = selection_sha256
    write_canonical_json(path, record)
    _log("sealed", record)


def require_lease(*, tag_root: Path, lease: dict, selection_sha256: str, reference: dict) -> None:
    record = _read(_path(tag_root, lease), tag_root.name)
    _require_live(lease)
    _matches(DIGEST_RE, selection_sha256, "selection digest")
    if (
        record["lease"] != lease
        or record["selection_sha256"] != selection_sha256
        or reference not in record["references"]
    ):
        raise IdbCacheError("Selection lease owner, digest, or generation binding mismatch")


def release_lease(*, tag_root: Path, lease: dict, selection_sha256: str) -> None:
    path = _path(tag_root, lease)
    if not _plain(path, directory=False):
        return
    record = _read(path, tag_root.name)
    if record["lease"] != lease or record["selection_sha256"] != selection_sha256:
        raise IdbCacheError("Cannot release another selection's lease")
    path.unlink()
    _log("released", record)


def protected_generations(*, tag_root: Path, now: datetime) -> set[str]:
    """Validate the entire lease inventory before reclaiming anything (fail closed)."""
    directory = _directory(tag_root)
    if not directory.exists():
        return set()
    keep = set()
    expired = []
    temporary = []
    for path in sorted(directory.iterdir()):
        _plain(path, directory=False)
        if TEMPORARY_RE.fullmatch(path.name):
            # Atomic-write scratch cannot authorize a consumer before its final rename.
            if now - datetime.fromtimestamp(path.stat().st_mtime, timezone.utc) >= LEASE_LIFETIME:
                temporary.append(path)
            continue
        record = _read(path, tag_root.name)
        if now >= _time(record["lease"]["expires_at"]) + CLOCK_SKEW_ALLOWANCE:
            expired.append((path, record))
        else:
            keep.update(ref["generation"] for ref in record["references"])
    for path, record in expired:
        path.unlink()
        _log("expired", record)
    for path in temporary:
        path.unlink()
        print(f"IDB cache lease expired scratch removed: {path}", flush=True)
    return keep
