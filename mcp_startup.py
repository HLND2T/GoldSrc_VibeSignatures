"""Runner-local cross-process MCP startup lock for dynamic-port idalib-mcp launches.

The lock only serializes the short allocate/spawn/bind-confirmation window so
concurrent analyzers cannot race each other onto the same ephemeral MCP port.
It is intentionally not held for full IDA readiness or the whole analysis.
"""

from __future__ import annotations

import contextlib
import os
import tempfile
from pathlib import Path

MCP_STARTUP_LOCK_DIR_ENV = "GSVIBE_MCP_STARTUP_LOCK_DIR"
MCP_STARTUP_LOCK_FILENAME = "gsvibe-mcp-startup.lock"
DEFAULT_LOCK_TIMEOUT_SECONDS = 120.0


class McpStartupLockError(RuntimeError):
    pass


def mcp_startup_lock_path() -> Path:
    """Resolve the shared lock path from RUNNER_TEMP (or the local temp fallback)."""
    configured = os.environ.get(MCP_STARTUP_LOCK_DIR_ENV)
    if configured and str(configured).strip():
        root = Path(str(configured).strip())
    else:
        runner_temp = os.environ.get("RUNNER_TEMP")
        if runner_temp and str(runner_temp).strip():
            root = Path(str(runner_temp).strip())
        else:
            root = Path(tempfile.gettempdir())
    try:
        root.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise McpStartupLockError(f"unable to prepare MCP startup lock directory {root}: {exc}") from exc
    return root / MCP_STARTUP_LOCK_FILENAME


@contextlib.contextmanager
def mcp_startup_lock(path: Path | None = None, *, timeout_seconds: float = DEFAULT_LOCK_TIMEOUT_SECONDS):
    """Hold an exclusive advisory lock across processes for the MCP bind window."""
    import time

    lock_path = mcp_startup_lock_path() if path is None else Path(path)
    handle = open(lock_path, "a+b")
    acquired = False
    deadline = time.monotonic() + max(0.0, timeout_seconds)
    try:
        while True:
            acquired = _try_lock(handle)
            if acquired:
                break
            if time.monotonic() >= deadline:
                raise McpStartupLockError(
                    f"timed out acquiring MCP startup lock {lock_path} after {timeout_seconds:g}s"
                )
            time.sleep(0.1)
        yield lock_path
    finally:
        if acquired:
            _unlock(handle)
        handle.close()


def _try_lock(handle) -> bool:
    if os.name == "nt":
        import msvcrt

        try:
            msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            return True
        except OSError:
            return False
    import fcntl

    try:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        return True
    except OSError:
        return False


def _unlock(handle) -> None:
    if os.name == "nt":
        import msvcrt

        try:
            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
        except OSError:
            pass
    else:
        import fcntl

        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        except OSError:
            pass
