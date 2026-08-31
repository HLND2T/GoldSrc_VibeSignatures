"""Non-blocking file locks for persisted accepted-bin maintenance.

One lock per game version lives under ``<persisted-root>/accepted-bin/locks`` and serializes
materialization, legacy cleanup, and other maintenance of ``bin/<gamever>``.

Both are byte-range locks held by an open handle: process exit releases them and the lock
file is deliberately left behind.
"""

from __future__ import annotations

import os
from contextlib import contextmanager
from pathlib import Path

from release_workflow_lib.errors import ReleaseWorkflowError
from release_workflow_lib.hashing import contained_path
from release_workflow_lib.manifests import require_gamever

LOCK_RELATIVE = ("accepted-bin", "locks")


@contextmanager
def version_lock(lock_path: Path):
    lock_path = Path(lock_path)
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    handle = lock_path.open("a+b")
    try:
        handle.seek(0, os.SEEK_END)
        if handle.tell() == 0:
            handle.write(b"0")
            handle.flush()
        if os.name == "nt":
            import msvcrt

            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl

            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    except OSError as exc:
        raise ReleaseWorkflowError(f"unable to acquire persisted workspace lock: {lock_path}") from exc
    finally:
        try:
            if os.name == "nt":
                import msvcrt

                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        except OSError:
            pass
        handle.close()


def accepted_bin_lock_path(persisted_root: str | Path, gamever: str) -> Path:
    return contained_path(persisted_root, *LOCK_RELATIVE, f"{require_gamever(gamever)}.lock")
