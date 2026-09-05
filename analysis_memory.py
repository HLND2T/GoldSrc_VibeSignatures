"""Aggregate process-tree memory authority for GoldSrc analyzer invocations.

Reuses the Windows Job Object primitives from ``warmup_memory`` while keeping a
separate configuration surface (``GSVIBE_ANALYSIS_*``) and diagnostics for the
full-analysis coordinator and direct single-tag/selected-node analysis paths.
"""

from __future__ import annotations

import ctypes
import os
import threading
import time
from ctypes import wintypes
from dataclasses import dataclass
from typing import Callable, Protocol

from warmup_memory import (
    DEFAULT_SOFT_LIMIT_RATIO,
    MIB,
    DEFAULT_INITIAL_WORKER_RESERVATION_BYTES,
    MemoryLaunchGate,
    MemorySnapshot,
    WindowsJobMemoryController,
)

ANALYSIS_CONCURRENCY_ENV = "GSVIBE_ANALYSIS_MAX_CONCURRENCY"
ANALYSIS_MEMORY_ENV = "GSVIBE_ANALYSIS_MAX_MEMORY_MIB"
COORDINATED_CHILD_ENV = "GSVIBE_ANALYSIS_COORDINATED_CHILD"
MAX_ANALYSIS_CONCURRENCY = 32
DEFAULT_ANALYSIS_CONCURRENCY = 1


class AnalysisMemoryConfigError(ValueError):
    pass


def parse_analysis_concurrency(raw: str | None = None) -> int:
    """Parse GSVIBE_ANALYSIS_MAX_CONCURRENCY; fail closed on any malformed value."""
    value = os.environ.get(ANALYSIS_CONCURRENCY_ENV) if raw is None else raw
    if value is None or not str(value).strip():
        return DEFAULT_ANALYSIS_CONCURRENCY
    text = str(value).strip()
    if not text.isdecimal() or not text.isascii():
        raise AnalysisMemoryConfigError(
            f"{ANALYSIS_CONCURRENCY_ENV} must be a decimal integer from 1 to {MAX_ANALYSIS_CONCURRENCY}"
        )
    concurrency = int(text, 10)
    if not 1 <= concurrency <= MAX_ANALYSIS_CONCURRENCY:
        raise AnalysisMemoryConfigError(
            f"{ANALYSIS_CONCURRENCY_ENV} must be a decimal integer from 1 to {MAX_ANALYSIS_CONCURRENCY}"
        )
    return concurrency


def parse_analysis_memory_budget_bytes(raw: str | None = None) -> int | None:
    """Parse GSVIBE_ANALYSIS_MAX_MEMORY_MIB; unset or empty disables the guard."""
    value = os.environ.get(ANALYSIS_MEMORY_ENV) if raw is None else raw
    if value is None or not str(value).strip():
        return None
    text = str(value).strip()
    if not text.isdecimal() or not text.isascii():
        raise AnalysisMemoryConfigError(f"{ANALYSIS_MEMORY_ENV} must be a positive decimal integer MiB value")
    memory_mib = int(text, 10)
    if memory_mib < 1:
        raise AnalysisMemoryConfigError(f"{ANALYSIS_MEMORY_ENV} must be a positive decimal integer MiB value")
    return memory_mib * MIB


@dataclass(frozen=True)
class AnalysisMemoryLimits:
    max_concurrency: int
    memory_budget_bytes: int | None

    @property
    def memory_guard_enabled(self) -> bool:
        return self.memory_budget_bytes is not None


def resolve_analysis_limits(
    *,
    concurrency_raw: str | None = None,
    memory_raw: str | None = None,
) -> AnalysisMemoryLimits:
    return AnalysisMemoryLimits(
        max_concurrency=parse_analysis_concurrency(concurrency_raw),
        memory_budget_bytes=parse_analysis_memory_budget_bytes(memory_raw),
    )


def validate_limits_for_effective_concurrency(limits: AnalysisMemoryLimits, effective_concurrency: int) -> None:
    """Fail closed before any worker starts when parallel mode lacks a memory budget."""
    if effective_concurrency > 1 and not limits.memory_guard_enabled:
        raise AnalysisMemoryConfigError(
            f"{ANALYSIS_MEMORY_ENV} must be set when effective analysis concurrency exceeds 1"
        )


class _MemoryStatusEx(ctypes.Structure):
    _fields_ = [
        ("dwLength", wintypes.DWORD),
        ("dwMemoryLoad", wintypes.DWORD),
        ("ullTotalPhys", ctypes.c_ulonglong),
        ("ullAvailPhys", ctypes.c_ulonglong),
        ("ullTotalPageFile", ctypes.c_ulonglong),
        ("ullAvailPageFile", ctypes.c_ulonglong),
        ("ullTotalVirtual", ctypes.c_ulonglong),
        ("ullAvailVirtual", ctypes.c_ulonglong),
        ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
    ]


class HostMemoryProbe(Protocol):
    def available_physical_bytes(self) -> int: ...


class WindowsGlobalMemoryStatusProbe:
    """Read host available physical memory via GlobalMemoryStatusEx."""

    def __init__(self) -> None:
        if os.name != "nt" or not hasattr(ctypes, "WinDLL"):
            raise OSError("host memory probing requires Windows")
        self._kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self._kernel32.GlobalMemoryStatusEx.argtypes = [ctypes.POINTER(_MemoryStatusEx)]
        self._kernel32.GlobalMemoryStatusEx.restype = wintypes.BOOL

    def available_physical_bytes(self) -> int:
        status = _MemoryStatusEx()
        status.dwLength = ctypes.sizeof(_MemoryStatusEx)
        if not self._kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
            raise ctypes.WinError(ctypes.get_last_error())
        return int(status.ullAvailPhys)


class AnalysisMemoryGate(MemoryLaunchGate):
    """Memory launch gate with an additional host-headroom admission signal."""

    def __init__(self, *, host_probe: HostMemoryProbe | None = None, **kwargs) -> None:
        super().__init__(**kwargs)
        self._host_probe = host_probe

    def _admission_state(self, snapshot: MemorySnapshot, now: float) -> tuple[bool, str]:
        admitted, reason = super()._admission_state(snapshot, now)
        if admitted and self._host_probe is not None:
            host_available = self._host_probe.available_physical_bytes()
            reservation = self._worker_reservation(snapshot)
            if host_available < reservation:
                return (
                    False,
                    f"host available {_format_mib(host_available)} below worker reservation {_format_mib(reservation)}",
                )
        return admitted, reason

    def try_admit(self, worker_name: str) -> str | None:
        """Attempt one non-blocking admission; return the wait reason when not admitted."""
        with self._condition:
            snapshot = self._snapshot()
            now = self._monotonic()
            admitted, reason = self._admission_state(snapshot, now)
            if not admitted:
                return reason
            self._active_workers += 1
            self._last_launch_time = now
            return None

    def wait_for_launch(self, worker_name: str, *, timeout_seconds: float) -> None:
        """Wait for admission and report the final wait reason on timeout."""
        import math

        if not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
            raise ValueError("memory admission timeout must be positive and finite")
        with self._condition:
            deadline = self._monotonic() + timeout_seconds
            reason = ""
            while True:
                snapshot = self._snapshot()
                now = self._monotonic()
                admitted, reason = self._admission_state(snapshot, now)
                if admitted:
                    self._active_workers += 1
                    self._last_launch_time = now
                    return
                if now >= deadline:
                    raise TimeoutError(
                        f"analysis memory admission timed out after {timeout_seconds:g}s; last reason: {reason}"
                    )
                self._condition.wait(timeout=min(self._poll_interval_seconds, max(0, deadline - now)))


class AnalysisMemoryAuthority:
    """Own the single Job controller and one launch gate across both analysis phases."""

    def __init__(
        self,
        budget_bytes: int,
        *,
        controller_factory: Callable[[int], WindowsJobMemoryController] = WindowsJobMemoryController,
        host_probe: HostMemoryProbe | None = None,
        soft_limit_ratio: float = DEFAULT_SOFT_LIMIT_RATIO,
        initial_worker_reservation_bytes: int = DEFAULT_INITIAL_WORKER_RESERVATION_BYTES,
        poll_interval_seconds: float = 2.0,
        launch_interval_seconds: float = 5.0,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        if budget_bytes < 1:
            raise AnalysisMemoryConfigError("analysis memory budget must be positive when enabled")
        self.budget_bytes = budget_bytes
        self._soft_limit_bytes = int(budget_bytes * soft_limit_ratio)
        self._initial_worker_reservation_bytes = initial_worker_reservation_bytes
        self._controller = controller_factory(budget_bytes)
        baseline = self._controller.snapshot()
        if baseline.job_bytes + initial_worker_reservation_bytes > self._soft_limit_bytes:
            raise AnalysisMemoryConfigError(
                "analysis memory budget cannot satisfy one worker reservation: "
                f"budget={_format_mib(budget_bytes)}, baseline={_format_mib(baseline.job_bytes)}, "
                f"reservation={_format_mib(initial_worker_reservation_bytes)}, "
                f"soft={_format_mib(self._soft_limit_bytes)}"
            )
        self._baseline_job_bytes = baseline.job_bytes
        self._gate = AnalysisMemoryGate(
            host_probe=host_probe,
            snapshot=self._controller.snapshot,
            budget_bytes=budget_bytes,
            baseline_job_bytes=baseline.job_bytes,
            soft_limit_ratio=soft_limit_ratio,
            initial_worker_reservation_bytes=initial_worker_reservation_bytes,
            poll_interval_seconds=poll_interval_seconds,
            launch_interval_seconds=launch_interval_seconds,
            monotonic=monotonic,
        )
        print(
            "Analysis memory controls enabled: "
            f"budget={_format_mib(budget_bytes)}; baseline={_format_mib(baseline.job_bytes)}; "
            f"soft={_format_mib(self._soft_limit_bytes)}; "
            f"reservation={_format_mib(initial_worker_reservation_bytes)}"
        )

    @property
    def gate(self) -> AnalysisMemoryGate:
        return self._gate

    @property
    def baseline_job_bytes(self) -> int:
        return self._baseline_job_bytes

    def snapshot(self) -> MemorySnapshot:
        return self._controller.snapshot()


_AUTHORITY_LOCK = threading.Lock()
_PROCESS_AUTHORITY: AnalysisMemoryAuthority | None = None


def is_coordinated_child(environ: dict | None = None) -> bool:
    source = os.environ if environ is None else environ
    return str(source.get(COORDINATED_CHILD_ENV, "")).strip() not in ("", "0", "false")


def analysis_memory_authority_from_environment() -> AnalysisMemoryAuthority | None:
    """Return the sole analysis memory owner for this PID; children inherit the parent Job."""
    if is_coordinated_child():
        print("Analysis memory guard: coordinated child inherits the parent Job authority")
        return None
    budget_bytes = parse_analysis_memory_budget_bytes()
    if budget_bytes is None:
        return None
    global _PROCESS_AUTHORITY
    with _AUTHORITY_LOCK:
        if _PROCESS_AUTHORITY is None:
            _PROCESS_AUTHORITY = AnalysisMemoryAuthority(budget_bytes)
        elif _PROCESS_AUTHORITY.budget_bytes != budget_bytes:
            raise AnalysisMemoryConfigError("analysis memory budget cannot change within one analyzer process")
        return _PROCESS_AUTHORITY


def _format_mib(value: int) -> str:
    return f"{value / MIB:.1f} MiB"
