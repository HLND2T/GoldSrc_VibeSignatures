"""Exact IDB cache selection primitives shared by the PR and release cache workflows.

A *selection* is the immutable contract between an IDB cache producer and its consumers:
the producer publishes immutable generations and records exactly which generation each
``(tag, platform)`` group must use, and every consumer restores those exact generations.
Consumers never re-probe ``READY.json``: READY is only a probe hint and another producer
may legitimately advance it between the producer and consumer jobs.

The concrete selection *documents* differ per caller (a PR selection binds the bound plan,
a release selection binds the source SHA and ``bin`` gitlink), but the entry shape, the
canonical ordering, the coverage/identity validation, the SHA-256 evidence file and the
locked restore are shared here so the two callers cannot drift apart.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

from ida_database_paths import is_reparse_point
from idb_cache import (
    CACHE_SCHEMA_VERSION,
    probe_generation,
    prune_tag,
    restore_generation,
    verify_selection,
    warm_and_publish,
)
from idb_cache_locks import (
    DEFAULT_TAG_LOCK_TIMEOUT_SECONDS,
    tag_lock,
    tag_lock_timeout_seconds,
)
from release_workflow_lib.hashing import (
    normalized_sha256,
    sha256_bytes,
    write_canonical_json,
)

SELECTION_ENTRY_KEYS = {"tag", "platform", "cache_key", "generation", "manifest_sha256", "binaries"}


class IdbCacheSelectionError(ValueError):
    pass


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _reject_reparse_ancestors(path: Path) -> None:
    absolute = path.absolute()
    for candidate in reversed((absolute, *absolute.parents)):
        if candidate.exists() and is_reparse_point(candidate):
            raise IdbCacheSelectionError(f"Persisted workspace traverses a link/reparse point: {candidate}")


def validate_persisted_workspace(persisted_root: str | Path, checkout_root: str | Path) -> Path:
    persisted_path = Path(persisted_root)
    checkout_path = Path(checkout_root)
    if not persisted_path.is_dir():
        raise IdbCacheSelectionError("Persisted workspace must be a pre-provisioned directory")
    if not checkout_path.is_dir():
        raise IdbCacheSelectionError("Checkout root is missing")
    _reject_reparse_ancestors(persisted_path)
    persisted = persisted_path.resolve()
    checkout = checkout_path.resolve()
    if _is_within(persisted, checkout) or _is_within(checkout, persisted):
        raise IdbCacheSelectionError("Persisted workspace and checkout must not overlap")
    return persisted


def entry_sort_key(entry: dict) -> tuple[bytes, bytes]:
    return (entry["tag"].encode("utf-8"), entry["platform"].encode("utf-8"))


def generation_selection(entry: dict) -> dict:
    """Project a selection entry onto the exact immutable generation selection."""
    return {
        "schema_version": CACHE_SCHEMA_VERSION,
        "tag": entry["tag"],
        "cache_key": entry["cache_key"],
        "generation": entry["generation"],
        "manifest_sha256": entry["manifest_sha256"],
    }


def selection_entry(*, tag: str, platform: str, selection: dict, binaries: list[dict]) -> dict:
    return {
        "tag": tag,
        "platform": platform,
        "cache_key": selection["cache_key"],
        "generation": selection["generation"],
        "manifest_sha256": selection["manifest_sha256"],
        "binaries": list(binaries),
    }


def validate_selection_entries(
    *,
    entries: object,
    identities: dict[tuple[str, str], dict],
    persisted_root: str | Path,
) -> None:
    """Assert the entries cover exactly the expected groups and bind exact generations.

    ``identities`` is rebuilt from the current workspace binaries and the pinned IDA runtime,
    so matching it proves the consumer sees the same inputs the producer cached.
    """
    if not isinstance(entries, list) or entries != sorted(entries, key=entry_sort_key):
        raise IdbCacheSelectionError("Cache selection entries must use canonical order")
    if len(entries) != len(identities):
        raise IdbCacheSelectionError("Cache selection does not cover every expected binary group")
    seen = set()
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != SELECTION_ENTRY_KEYS:
            raise IdbCacheSelectionError("Cache selection entry has unexpected fields")
        pair = (entry["tag"], entry["platform"])
        if pair in seen or pair not in identities:
            raise IdbCacheSelectionError("Cache selection contains an unexpected or duplicate tag/platform group")
        seen.add(pair)
        identity = identities[pair]
        if entry["binaries"] != identity["binaries"]:
            raise IdbCacheSelectionError("Cache selection binary identities do not match the expected workspace")
        manifest = verify_selection(persisted_root=persisted_root, selection=generation_selection(entry))
        if manifest["identity"] != identity:
            raise IdbCacheSelectionError("Cache generation identity does not match the pinned runtime and binaries")


def prepare_selection_entries(
    *,
    groups,
    identities: dict[tuple[str, str], dict],
    persisted_root: str | Path,
    run_id: str,
    attempt: int,
    timeout_seconds: float,
) -> list[dict]:
    """Probe, warm and publish every group under its tag lock, returning canonical entries."""
    persisted = Path(persisted_root)
    entries = []
    for group in groups:
        identity = identities[(group.tag, group.platform)]
        started = time.monotonic()
        with tag_lock(persisted, group.tag, timeout_seconds=tag_lock_timeout_seconds(timeout_seconds)):
            selection = probe_generation(persisted_root=persisted, identity=identity)
            hit = selection is not None
            if selection is None:
                selection = warm_and_publish(
                    persisted_root=persisted,
                    identity=identity,
                    workspace_root=group.workspace_root,
                    run_id=run_id,
                    attempt=attempt,
                    timeout_seconds=timeout_seconds,
                )
            verify_selection(persisted_root=persisted, selection=selection)
            prune_tag(persisted_root=persisted, tag=group.tag)
        entries.append(
            selection_entry(
                tag=group.tag,
                platform=group.platform,
                selection=selection,
                binaries=identity["binaries"],
            )
        )
        print(
            f"IDB cache {'hit' if hit else 'miss'}: {group.tag}/{group.platform}; "
            f"binaries={len(group.binaries)}; generation={selection['generation']}; "
            f"manifest_sha256={selection['manifest_sha256']}; wall_seconds={time.monotonic() - started:.3f}"
        )
    return sorted(entries, key=entry_sort_key)


def restore_selection_entries(
    *,
    entries: list[dict],
    groups,
    persisted_root: str | Path,
    timeout_seconds: float = DEFAULT_TAG_LOCK_TIMEOUT_SECONDS,
) -> None:
    """Restore each exact generation into its workspace while holding that tag's lock.

    The lock spans verify and restore so a concurrent producer cannot prune the generation
    between the moment it is validated and the moment its bytes are copied out.
    """
    group_map = {(group.tag, group.platform): group for group in groups}
    for entry in entries:
        pair = (entry["tag"], entry["platform"])
        if pair not in group_map:
            raise IdbCacheSelectionError(f"Cache selection entry has no workspace group: {pair[0]}/{pair[1]}")
        selection = generation_selection(entry)
        started = time.monotonic()
        with tag_lock(persisted_root, entry["tag"], timeout_seconds=timeout_seconds):
            verify_selection(persisted_root=persisted_root, selection=selection)
            restore_generation(
                persisted_root=persisted_root,
                selection=selection,
                workspace_root=group_map[pair].workspace_root,
            )
        print(
            f"IDB cache restored: {entry['tag']}/{entry['platform']}; generation={entry['generation']}; "
            f"wall_seconds={time.monotonic() - started:.3f}"
        )


def write_selection_with_evidence(
    *, document: dict, output_path: str | Path, output_sha256_path: str | Path
) -> tuple[bytes, str]:
    write_canonical_json(output_path, document)
    raw = Path(output_path).read_bytes()
    digest = sha256_bytes(raw)
    Path(output_sha256_path).write_text(f"{digest}\n", encoding="ascii", newline="\n")
    return raw, digest


def read_selection_with_evidence(
    *, selection_path: str | Path, selection_sha256_path: str | Path
) -> tuple[dict, bytes, str]:
    raw = Path(selection_path).read_bytes()
    expected_digest = Path(selection_sha256_path).read_text(encoding="ascii").strip()
    normalized_sha256(expected_digest, "cache selection SHA-256")
    digest = sha256_bytes(raw)
    if digest != expected_digest:
        raise IdbCacheSelectionError("Cache selection SHA-256 evidence mismatch")
    try:
        document = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise IdbCacheSelectionError(f"Unable to parse cache selection: {exc}") from exc
    return document, raw, digest
