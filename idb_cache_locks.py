"""Cross-process file locks that serialize persisted IDB cache mutations.

This is the lowest layer of the IDB cache stack: it owns the shared error type and the
byte-range locks, so every writer (warm worker, publisher, pruner, restorer) can be
serialized without any module importing the cache core.

Lock authority rules:

* ``tag_lock`` guards the whole ``probe -> warm/publish -> verify -> selection -> prune``
  and ``verify -> restore`` critical sections for one tag. Publishing, rebuilding READY,
  pruning and restoring must all hold it, otherwise a pruner can delete the exact
  generation a restore already selected.
* ``warm_port_lock_path`` guards the fixed MCP port used by the neutral warm worker.
* A lock is held by an open handle, never by the presence of the lock file. Process exit
  releases it; the file is deliberately left behind.
"""

from __future__ import annotations

import os
import time
from contextlib import contextmanager
from pathlib import Path

from analysis_config import validated_tag

DEFAULT_LOCK_TIMEOUT_SECONDS = 120.0
DEFAULT_LOCK_WAIT_INTERVAL_SECONDS = 0.1
DEFAULT_WARM_TIMEOUT_SECONDS = 3600.0
# A tag lock is held across the whole warm worker run plus publish/verify/prune, so it must
# outlast the worker timeout instead of expiring while the first writer is still legitimately busy.
TAG_LOCK_PUBLISH_MARGIN_SECONDS = 900.0
DEFAULT_TAG_LOCK_TIMEOUT_SECONDS = DEFAULT_WARM_TIMEOUT_SECONDS + TAG_LOCK_PUBLISH_MARGIN_SECONDS


class IdbCacheError(ValueError):
    pass


def _acquire(handle, /) -> None:
    if os.name == "nt":
        import msvcrt

        handle.seek(0)
        if handle.tell() == handle.seek(0, os.SEEK_END):
            handle.write(b"\0")
            handle.flush()
        handle.seek(0)
        msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
        return
    import fcntl

    fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)


def _release(handle, /) -> None:
    if os.name == "nt":
        import msvcrt

        handle.seek(0)
        msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
        return
    import fcntl

    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


@contextmanager
def exclusive_file_lock(
    path: str | Path,
    timeout_seconds: float = DEFAULT_LOCK_TIMEOUT_SECONDS,
    *,
    wait_interval_seconds: float = DEFAULT_LOCK_WAIT_INTERVAL_SECONDS,
    description: str = "IDB cache file lock",
):
    lock_path = Path(path)
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    handle = lock_path.open("a+b")
    deadline = time.monotonic() + timeout_seconds
    acquired = False
    try:
        while not acquired:
            try:
                _acquire(handle)
                acquired = True
            except OSError:
                if time.monotonic() >= deadline:
                    raise IdbCacheError(
                        f"Timed out after {timeout_seconds:g}s acquiring {description}: {lock_path}"
                    ) from None
                time.sleep(wait_interval_seconds)
        yield
    finally:
        if acquired:
            _release(handle)
        handle.close()


def lock_root(persisted_root: str | Path) -> Path:
    root = Path(persisted_root) / "idb-cache" / ".locks"
    root.mkdir(parents=True, exist_ok=True)
    return root


def warm_port_lock_path(persisted_root: str | Path) -> Path:
    return lock_root(persisted_root) / "ida-mcp-port.lock"


def tag_lock_timeout_seconds(warm_timeout_seconds: float = DEFAULT_WARM_TIMEOUT_SECONDS) -> float:
    return float(warm_timeout_seconds) + TAG_LOCK_PUBLISH_MARGIN_SECONDS


@contextmanager
def tag_lock(
    persisted_root: str | Path,
    tag: str,
    *,
    timeout_seconds: float = DEFAULT_TAG_LOCK_TIMEOUT_SECONDS,
):
    try:
        tag = validated_tag(tag)
    except (TypeError, ValueError, RuntimeError) as exc:
        raise IdbCacheError(f"Invalid cache tag for the tag lock: {exc}") from exc
    with exclusive_file_lock(
        lock_root(persisted_root) / f"{tag}.lock",
        timeout_seconds,
        description=f"IDB cache tag lock for {tag}",
    ):
        yield
