"""Cross-process SMB-safe byte-range locks for persisted IDB cache coordination."""

from __future__ import annotations

import ctypes
import errno
import math
import os
import time
from contextlib import contextmanager
from ctypes import wintypes
from pathlib import Path

from analysis_config import validated_tag

DEFAULT_LOCK_TIMEOUT_SECONDS = 120.0
DEFAULT_LOCK_WAIT_INTERVAL_SECONDS = 0.1
_ERROR_LOCK_VIOLATION = 33
_LOCKFILE_FAIL_IMMEDIATELY = 0x00000001
_LOCKFILE_EXCLUSIVE_LOCK = 0x00000002


class IdbCacheError(ValueError):
    pass


class _Overlapped(ctypes.Structure):
    _fields_ = [
        ("Internal", ctypes.c_size_t),
        ("InternalHigh", ctypes.c_size_t),
        ("Offset", wintypes.DWORD),
        ("OffsetHigh", wintypes.DWORD),
        ("hEvent", wintypes.HANDLE),
    ]


def _windows_lock_api():
    import msvcrt

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.LockFileEx.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(_Overlapped),
    ]
    kernel32.LockFileEx.restype = wintypes.BOOL
    kernel32.UnlockFileEx.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(_Overlapped),
    ]
    kernel32.UnlockFileEx.restype = wintypes.BOOL
    return kernel32, msvcrt


def _acquire(handle, /) -> None:
    if os.name == "nt":
        kernel32, msvcrt = _windows_lock_api()
        overlapped = _Overlapped()
        os_handle = wintypes.HANDLE(msvcrt.get_osfhandle(handle.fileno()))
        if not kernel32.LockFileEx(
            os_handle,
            _LOCKFILE_EXCLUSIVE_LOCK | _LOCKFILE_FAIL_IMMEDIATELY,
            0,
            1,
            0,
            ctypes.byref(overlapped),
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        return
    import fcntl

    fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)


def _release(handle, /) -> None:
    if os.name == "nt":
        kernel32, msvcrt = _windows_lock_api()
        overlapped = _Overlapped()
        os_handle = wintypes.HANDLE(msvcrt.get_osfhandle(handle.fileno()))
        if not kernel32.UnlockFileEx(os_handle, 0, 1, 0, ctypes.byref(overlapped)):
            raise ctypes.WinError(ctypes.get_last_error())
        return
    import fcntl

    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def _is_contention(error: OSError) -> bool:
    if os.name == "nt":
        return getattr(error, "winerror", None) == _ERROR_LOCK_VIOLATION
    return error.errno in {errno.EACCES, errno.EAGAIN}


def _error_code(error: OSError) -> str:
    winerror = getattr(error, "winerror", None)
    if winerror is not None:
        return f"winerror={winerror}"
    if error.errno is not None:
        return f"errno={error.errno}"
    return "code=unknown"


def _lock_failure(description: str, phase: str, error: OSError) -> IdbCacheError:
    return IdbCacheError(f"Unable to {phase} {description}: {type(error).__name__} ({_error_code(error)})")


@contextmanager
def exclusive_file_lock(
    path: str | Path,
    timeout_seconds: float | None = DEFAULT_LOCK_TIMEOUT_SECONDS,
    *,
    wait_interval_seconds: float = DEFAULT_LOCK_WAIT_INTERVAL_SECONDS,
    description: str = "IDB cache file lock",
):
    if timeout_seconds is not None and (
        not isinstance(timeout_seconds, (int, float))
        or isinstance(timeout_seconds, bool)
        or not math.isfinite(timeout_seconds)
        or timeout_seconds < 0
    ):
        raise IdbCacheError("Lock timeout must be a finite non-negative number or None")
    if wait_interval_seconds < 0:
        raise IdbCacheError("Lock wait interval must be non-negative")

    lock_path = Path(path)
    handle = None
    acquired = False
    primary_error: BaseException | None = None
    try:
        try:
            lock_path.parent.mkdir(parents=True, exist_ok=True)
            handle = lock_path.open("a+b")
            handle.seek(0, os.SEEK_END)
            if handle.tell() == 0:
                handle.write(b"\0")
                handle.flush()
            handle.seek(0)
        except OSError as error:
            raise _lock_failure(description, "open", error) from error

        deadline = None if timeout_seconds is None else time.monotonic() + timeout_seconds
        while True:
            try:
                _acquire(handle)
                acquired = True
                break
            except OSError as error:
                if not _is_contention(error):
                    raise _lock_failure(description, "acquire", error) from error
                if deadline is not None and time.monotonic() >= deadline:
                    raise IdbCacheError(f"Timed out after {timeout_seconds:g}s acquiring {description}") from None
                time.sleep(wait_interval_seconds)
        yield
    except BaseException as error:
        primary_error = error
        raise
    finally:
        cleanup_error = None
        if acquired and handle is not None:
            try:
                _release(handle)
            except OSError as error:
                cleanup_error = _lock_failure(description, "release", error)
        if handle is not None:
            try:
                handle.close()
            except OSError as error:
                if cleanup_error is None:
                    cleanup_error = _lock_failure(description, "close", error)
        if cleanup_error is not None and primary_error is None:
            raise cleanup_error


def lock_root(persisted_root: str | Path) -> Path:
    root = Path(persisted_root) / "idb-cache" / ".locks"
    try:
        root.mkdir(parents=True, exist_ok=True)
    except OSError as error:
        raise _lock_failure("IDB cache lock root", "create", error) from error
    return root


def producer_lock_path(persisted_root: str | Path) -> Path:
    return lock_root(persisted_root) / "producer.lock"


@contextmanager
def producer_lock(persisted_root: str | Path, *, timeout_seconds: float | None = None):
    with exclusive_file_lock(
        producer_lock_path(persisted_root),
        timeout_seconds,
        description="IDB cache producer lock",
    ):
        yield


@contextmanager
def tag_lock(
    persisted_root: str | Path,
    tag: str,
    *,
    timeout_seconds: float | None = None,
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
