"""Exact IDB cache selection primitives shared by the PR and release cache workflows.

A *selection* is the immutable contract between an IDB cache producer and its consumers:
the producer publishes immutable generations and records exactly which generation each
binary must use, and every consumer restores those exact generations.
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
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from pathlib import Path

from ida_database_paths import is_reparse_point
from idb_cache import (
    CACHE_SCHEMA_VERSION,
    _tag_root,
    _resolved_max_concurrency,
    publish_generation,
    probe_generation,
    prune_tag,
    restore_generation,
    verify_selection,
    warm_group,
)
from idb_cache_leases import (
    lease_reference,
    pin_generation,
    release_lease,
    reference_sort_key,
    require_lease,
    seal_lease,
    validate_lease,
)
from idb_cache_locks import tag_lock
from release_workflow_lib.hashing import (
    canonical_json_bytes,
    normalized_sha256,
    sha256_bytes,
    write_canonical_json,
)
from warmup_memory import ProducerMemoryOwner

SELECTION_ENTRY_KEYS = {"tag", "platform", "cache_key", "generation", "manifest_sha256", "binaries"}
SELECTION_SCHEMA_VERSION = 3


class IdbCacheSelectionError(ValueError):
    pass


@contextmanager
def timed_stage(stage: str):
    started = time.monotonic()
    print(f"IDB cache stage started: {stage}", flush=True)
    try:
        yield
    finally:
        print(f"IDB cache stage ended: {stage}; wall_seconds={time.monotonic() - started:.3f}", flush=True)


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


def binary_selection_key(tag: str, platform: str, binary: dict) -> tuple[str, str, str, str]:
    return (tag, platform, binary["module"], binary["path"])


def entry_sort_key(entry: dict) -> tuple[bytes, ...]:
    return tuple(
        part.encode("utf-8") for part in binary_selection_key(entry["tag"], entry["platform"], entry["binaries"][0])
    )


def per_binary_identities(identities: dict[tuple[str, str], dict]) -> dict[tuple[str, str, str, str], dict]:
    """Project warming batches onto independent immutable binary cache identities."""
    result = {}
    for (tag, platform), identity in identities.items():
        for binary in identity["binaries"]:
            key = binary_selection_key(tag, platform, binary)
            if key in result:
                raise IdbCacheSelectionError("Expected cache identities contain a duplicate binary")
            result[key] = {**identity, "binaries": [binary]}
    return result


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
    lease: dict,
    selection_sha256: str,
) -> None:
    """Assert the entries cover exactly the expected binaries and bind exact generations.

    ``identities`` is rebuilt from the current workspace binaries and the pinned IDA runtime,
    so matching it proves the consumer sees the same inputs the producer cached.
    """
    if not isinstance(entries, list) or any(
        not isinstance(entry, dict)
        or set(entry) != SELECTION_ENTRY_KEYS
        or not isinstance(entry["tag"], str)
        or not isinstance(entry["platform"], str)
        or not isinstance(entry["binaries"], list)
        or len(entry["binaries"]) != 1
        or not isinstance(entry["binaries"][0], dict)
        or not isinstance(entry["binaries"][0].get("module"), str)
        or not isinstance(entry["binaries"][0].get("path"), str)
        for entry in entries
    ):
        raise IdbCacheSelectionError("Cache selection entry has unexpected fields")
    if entries != sorted(entries, key=entry_sort_key):
        raise IdbCacheSelectionError("Cache selection entries must use canonical order")
    expected = per_binary_identities(identities)
    if len(entries) != len(expected):
        raise IdbCacheSelectionError("Cache selection does not cover every expected binary")
    seen = set()
    for entry in entries:
        key = binary_selection_key(entry["tag"], entry["platform"], entry["binaries"][0])
        if key in seen or key not in expected:
            raise IdbCacheSelectionError("Cache selection contains an unexpected or duplicate binary")
        seen.add(key)
        identity = expected[key]
        if entry["binaries"] != identity["binaries"]:
            raise IdbCacheSelectionError("Cache selection binary identities do not match the expected workspace")
    # Reject incomplete/duplicate identities before accessing any generation or lease.
    for entry in entries:
        identity = expected[binary_selection_key(entry["tag"], entry["platform"], entry["binaries"][0])]
        with tag_lock(persisted_root, entry["tag"], timeout_seconds=None):
            require_lease(
                tag_root=_tag_root(persisted_root, entry["tag"]),
                lease=lease,
                selection_sha256=selection_sha256,
                reference=lease_reference(entry),
            )
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
    ida_python_executable: str | Path,
    max_concurrency: int | None,
    worker_timeout_seconds: float,
    producer_memory: ProducerMemoryOwner,
    lease: dict,
    remote_cache=None,
) -> list[dict]:
    """Probe/cache each binary independently; warm misses in bounded platform batches.

    Tags probe concurrently. Miss batches run serially on the producer's single memory
    owner, with per-binary worker concurrency inside each batch. Every selected binary
    is pinned before unlocking; pruning visits each tag once after all its pins exist.
    """
    persisted = Path(persisted_root)
    concurrency = _resolved_max_concurrency(max_concurrency)
    validate_lease(lease)
    if lease["run_id"] != run_id or lease["attempt"] != attempt:
        raise IdbCacheSelectionError("Preparing lease must belong to the current producer run/attempt")
    groups = tuple(groups)
    binary_identities = per_binary_identities(identities)
    by_tag = {}
    for group in groups:
        by_tag.setdefault(group.tag, []).append(group)

    def group_keys(group):
        return [binary_selection_key(group.tag, group.platform, binary) for binary in group.binaries]

    def binary_label(key):
        tag, platform, module, path = key
        return f"tag={tag}; platform={platform}; module={module}; binary={path}"

    def pin(group, selection):
        pin_generation(
            tag_root=_tag_root(persisted, group.tag, create=True),
            lease=lease,
            reference=lease_reference({**selection, "platform": group.platform}),
        )

    def log_selection(key, selection, hit, elapsed):
        tag, platform, module, path = key
        print(
            f"IDB cache {'hit' if hit else 'miss'}: {tag}/{platform}; module={module}; binary={path}; "
            f"binaries=1; generation={selection['generation']}; "
            f"manifest_sha256={selection['manifest_sha256']}; wall_seconds={elapsed:.3f}",
            flush=True,
        )

    def probe_tag(tag_groups):
        results = {}
        protected = set()
        for group in tag_groups:
            if remote_cache is not None:
                with timed_stage(f"prepare_s3_prefetch; tag={group.tag}; platform={group.platform}"):
                    for key in group_keys(group):
                        remote_cache.prefetch(persisted, binary_identities[key])
            started = time.monotonic()
            with tag_lock(persisted, group.tag, timeout_seconds=None):
                print(
                    f"IDB cache initial tag lock acquired: tag={group.tag}; platform={group.platform}; "
                    f"wait_seconds={time.monotonic() - started:.3f}",
                    flush=True,
                )
                for key in group_keys(group):
                    started = time.monotonic()
                    with timed_stage(f"prepare_probe_verify; {binary_label(key)}"):
                        selection = probe_generation(persisted_root=persisted, identity=binary_identities[key])
                    if selection is not None:
                        # Probe fully verified this exact binary under the same tag lock.
                        pin(group, selection)
                        protected.add(selection["generation"])
                    elapsed = time.monotonic() - started
                    results[key] = (selection, elapsed)
                    if selection is not None:
                        log_selection(key, selection, True, elapsed)
        return results, protected

    probed = {}
    protected_by_tag = {}
    if by_tag:
        with timed_stage("prepare_parallel_probe_verify"):
            with ThreadPoolExecutor(max_workers=min(concurrency, len(by_tag))) as pool:
                # Exiting the pool waits for every task, including on failure. No warm or
                # selection publication starts until the complete probe phase succeeds.
                for tag, (results, protected) in zip(by_tag, pool.map(probe_tag, by_tag.values())):
                    probed.update(results)
                    protected_by_tag[tag] = protected

    entries = []
    for group in groups:
        keys = group_keys(group)
        misses = [key for key in keys if probed[key][0] is None]
        if misses:
            started = time.monotonic()
            label = f"tag={group.tag}; platform={group.platform}"
            with timed_stage(f"prepare_warm; {label}"):
                warm_group(
                    identity={
                        **identities[(group.tag, group.platform)],
                        "binaries": [binary_identities[key]["binaries"][0] for key in misses],
                    },
                    workspace_root=group.workspace_root,
                    ida_python_executable=ida_python_executable,
                    max_concurrency=concurrency,
                    worker_timeout_seconds=worker_timeout_seconds,
                    producer_memory=producer_memory,
                )
            publish_lock_started = time.monotonic()
            with tag_lock(persisted, group.tag, timeout_seconds=None):
                print(
                    f"IDB cache publish tag lock acquired: {label}; "
                    f"wait_seconds={time.monotonic() - publish_lock_started:.3f}",
                    flush=True,
                )
                for key in misses:
                    label = binary_label(key)
                    with timed_stage(f"prepare_publish_reprobe; {label}"):
                        selection = probe_generation(persisted_root=persisted, identity=binary_identities[key])
                    print(f"IDB cache publish re-probe: {label}; result={'hit' if selection else 'miss'}", flush=True)
                    if selection is None:
                        with timed_stage(f"prepare_publish; {label}"):
                            selection = publish_generation(
                                persisted_root=persisted,
                                identity=binary_identities[key],
                                workspace_root=group.workspace_root,
                                run_id=run_id,
                                attempt=attempt,
                            )
                    with timed_stage(f"prepare_published_verify; {label}"):
                        verify_selection(persisted_root=persisted, selection=selection)
                    protected_by_tag[group.tag].add(selection["generation"])
                    pin(group, selection)
                    probe_elapsed = probed[key][1]
                    probed[key] = (selection, probe_elapsed)
                    log_selection(key, selection, False, probe_elapsed + time.monotonic() - started)
        for key in keys:
            entries.append(
                selection_entry(
                    tag=group.tag,
                    platform=group.platform,
                    selection=probed[key][0],
                    binaries=binary_identities[key]["binaries"],
                )
            )
    for tag, protected in protected_by_tag.items():
        with tag_lock(persisted, tag, timeout_seconds=None), timed_stage(f"prepare_prune; tag={tag}"):
            prune_tag(persisted_root=persisted, tag=tag, protected_generations=protected)
    return sorted(entries, key=entry_sort_key)


def restore_selection_entries(
    *,
    entries: list[dict],
    groups,
    persisted_root: str | Path,
    lease: dict,
    selection_sha256: str,
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
        with tag_lock(persisted_root, entry["tag"], timeout_seconds=None):
            require_lease(
                tag_root=_tag_root(persisted_root, entry["tag"]),
                lease=lease,
                selection_sha256=selection_sha256,
                reference=lease_reference(entry),
            )
            verify_selection(persisted_root=persisted_root, selection=selection)
            restore_generation(
                persisted_root=persisted_root,
                selection=selection,
                workspace_root=group_map[pair].workspace_root,
            )
        print(
            f"IDB cache restored: {entry['tag']}/{entry['platform']}; generation={entry['generation']}; "
            f"wall_seconds={time.monotonic() - started:.3f}",
            flush=True,
        )
    # A partial restore keeps every pin, including those already copied, for retry.
    # Do not release from a finally block or after an individual platform succeeds.
    for tag in sorted({entry["tag"] for entry in entries}):
        with tag_lock(persisted_root, tag, timeout_seconds=None):
            release_lease(tag_root=_tag_root(persisted_root, tag), lease=lease, selection_sha256=selection_sha256)


def seal_selection_leases(*, document: dict, persisted_root: str | Path) -> None:
    """Bind every preparing pin before publishing any selection/evidence files."""
    digest = sha256_bytes(canonical_json_bytes(document))
    for tag in sorted({entry["tag"] for entry in document["entries"]}):
        references = sorted(
            (lease_reference(entry) for entry in document["entries"] if entry["tag"] == tag), key=reference_sort_key
        )
        with tag_lock(persisted_root, tag, timeout_seconds=None):
            seal_lease(
                tag_root=_tag_root(persisted_root, tag),
                lease=document["lease"],
                selection_sha256=digest,
                references=references,
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
