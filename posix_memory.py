"""POSIX aggregate memory controls for concurrent IDA workers (cgroup v2 or per-worker caps).

``warmup_memory`` imports this module lazily so the Windows ctypes path stays untouched; the
dependency is one-way (``posix_memory`` imports ``warmup_memory`` at module level).
"""

from __future__ import annotations

import os
import threading
from pathlib import Path, PurePosixPath
from typing import Callable, Protocol

from warmup_memory import MIB, MemoryControllerCapabilities, MemorySnapshot

DEFAULT_CGROUP_ROOT = "/sys/fs/cgroup"
PROC_SELF_CGROUP_PATH = "/proc/self/cgroup"
DEFAULT_PROC_ROOT = "/proc"
CGROUP_CHILD_NAME = "gsvibe-memory"
CGROUP_MEMORY_MAX = "memory.max"
CGROUP_MEMORY_CURRENT = "memory.current"
CGROUP_MEMORY_OOM_GROUP = "memory.oom.group"
CGROUP_MEMORY_SWAP_MAX = "memory.swap.max"
CGROUP_PROCS = "cgroup.procs"
CGROUP_MAX_VALUE = "max"
CGROUP_USAGE_MARGIN_BYTES = 64 * MIB
MINIMUM_ADDRESS_SPACE_LIMIT_MIB = 256
DEFAULT_WATCHDOG_INTERVAL_SECONDS = 2.0
# Fields after the ``comm`` field of /proc/<pid>/stat: 0=state, 1=ppid, 21=rss (kernel field 24).
_PROC_STAT_PPID_FIELD_INDEX = 1
_PROC_STAT_RSS_FIELD_INDEX = 21


class ProcessTreeResidentMemoryProbe(Protocol):
    def resident_bytes(self) -> int: ...


def parse_unified_cgroup_path(text: str) -> str:
    """Return the cgroup v2 path from ``/proc/self/cgroup`` contents."""
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if not lines:
        raise ValueError("empty cgroup listing")
    for line in lines:
        if not line.startswith("0::"):
            raise ValueError(f"not a unified cgroup v2 hierarchy: {line!r}")
    if len(lines) != 1:
        raise ValueError(f"expected exactly one cgroup line, found {len(lines)}")
    path = lines[0][3:]
    if not path.startswith("/"):
        raise ValueError(f"cgroup path is not absolute: {path!r}")
    return path


def read_process_cgroup_path(proc_self_cgroup_path: str = PROC_SELF_CGROUP_PATH) -> str:
    try:
        text = Path(proc_self_cgroup_path).read_text(encoding="ascii")
    except OSError as exc:
        raise ValueError(f"unable to read {proc_self_cgroup_path}: {exc}") from exc
    try:
        return parse_unified_cgroup_path(text)
    except ValueError as exc:
        raise ValueError(f"{proc_self_cgroup_path}: {exc}") from exc


def _read_text(path: Path) -> str:
    return path.read_text(encoding="ascii")


def _write_text(path: Path, value: str) -> None:
    path.write_text(value, encoding="ascii")


class ProcessTreeResidentMemoryProbe:
    """Sum the resident set of this process tree from ``/proc`` without ever raising."""

    def __init__(
        self,
        *,
        proc_root: str = DEFAULT_PROC_ROOT,
        pid: int | None = None,
        page_size: int | None = None,
    ) -> None:
        self._proc_root = Path(proc_root)
        self._pid = os.getpid() if pid is None else pid
        self._page_size = page_size

    def tree_pids_and_rss(self) -> tuple[tuple[int, ...], int]:
        """Return descendants before ancestors, followed by their summed resident bytes."""
        try:
            page_size = self._page_size if self._page_size is not None else os.sysconf("SC_PAGE_SIZE")
            entries = os.listdir(self._proc_root)
        except (AttributeError, OSError, ValueError):
            return (), 0
        children_by_pid: dict[int, list[int]] = {}
        rss_by_pid: dict[int, int] = {}
        for entry in entries:
            if not entry.isdigit():
                continue
            try:
                pid = int(entry)
                stat = (_read_text(self._proc_root / entry / "stat")).strip()
                closer = stat.rfind(")")
                if closer < 0:
                    continue
                fields = stat[closer + 2 :].split()
                if len(fields) <= _PROC_STAT_RSS_FIELD_INDEX:
                    continue
                parent = int(fields[_PROC_STAT_PPID_FIELD_INDEX])
                rss = int(fields[_PROC_STAT_RSS_FIELD_INDEX])
            except (OSError, ValueError):
                # /proc is a live view: an unrelated process may exit or be unreadable.
                continue
            children_by_pid.setdefault(parent, []).append(pid)
            rss_by_pid[pid] = rss
        members: set[int] = set()
        ancestors_first: list[int] = []
        pending = [self._pid]
        while pending:
            pid = pending.pop()
            if pid in members:
                continue
            members.add(pid)
            ancestors_first.append(pid)
            pending.extend(children_by_pid.get(pid, ()))
        # The watchdog may run inside the root itself. It must signal every descendant
        # before killing that root; PID ordering does not encode ancestry (PID wrap).
        ordered = tuple(reversed(ancestors_first))
        return ordered, sum(rss_by_pid.get(pid, 0) for pid in ordered) * page_size

    def tree_pids(self) -> tuple[int, ...]:
        return self.tree_pids_and_rss()[0]

    def resident_bytes(self) -> int:
        return self.tree_pids_and_rss()[1]


class ReservationMemoryController:
    """Account for real usage but delegate enforcement to per-worker hard caps."""

    def __init__(
        self,
        budget_bytes: int,
        *,
        reason: str,
        probe: ProcessTreeResidentMemoryProbe | None = None,
    ) -> None:
        if budget_bytes < 1:
            raise ValueError("budget_bytes must be positive")
        self.budget_bytes = budget_bytes
        self._probe = probe or ProcessTreeResidentMemoryProbe()
        self.capabilities = MemoryControllerCapabilities(
            tier="reservation-only",
            aggregate_hard_cap=False,
            detail=reason,
        )

    def snapshot(self) -> MemorySnapshot:
        return MemorySnapshot(job_bytes=self._probe.resident_bytes())


class CgroupV2MemoryController:
    """Bind this process to one cgroup v2 child capped at the aggregate budget.

    Only ever creates a new directory under the target cgroup and writes interface files inside
    it; ``cgroup.subtree_control`` is never written, because a cgroup with delegated controllers
    can no longer accept processes and would break its owner.
    """

    def __init__(
        self,
        budget_bytes: int,
        *,
        cgroup_root: str | Path = DEFAULT_CGROUP_ROOT,
        target_cgroup_path: str,
        source_cgroup_path: str,
        pid: int | None = None,
        oom_group: bool = True,
    ) -> None:
        if budget_bytes < 1:
            raise ValueError("budget_bytes must be positive")
        self.budget_bytes = budget_bytes
        self._pid = os.getpid() if pid is None else pid
        target = Path(cgroup_root) / target_cgroup_path.lstrip("/")
        if not target.is_dir():
            raise ValueError(f"cgroup target is not a directory: {target}")
        self._source_procs = Path(cgroup_root) / source_cgroup_path.lstrip("/") / CGROUP_PROCS
        child, created = self._claim_child_directory(target)
        self.cgroup_path = child
        self._created = created
        self._migrated = False
        try:
            self._require_memory_interface(child, target)
            self._enter(child, oom_group)
        except (OSError, ValueError):
            self._unwind()
            raise
        self.capabilities = MemoryControllerCapabilities(
            tier="cgroup-v2",
            aggregate_hard_cap=True,
            detail=f"cgroup v2 hard cap at {child}",
        )

    def _claim_child_directory(self, target: Path) -> tuple[Path, bool]:
        preferred = target / CGROUP_CHILD_NAME
        if self._is_reusable(preferred):
            return preferred, False
        if not preferred.exists():
            return self._create_child_directory(preferred, target), True
        exclusive = target / f"{CGROUP_CHILD_NAME}.{self._pid}"
        if exclusive.exists():
            raise ValueError(f"cgroup child already in use: {exclusive}")
        return self._create_child_directory(exclusive, target), True

    @staticmethod
    def _create_child_directory(child: Path, target: Path) -> Path:
        try:
            child.mkdir()
        except OSError as exc:
            raise ValueError(f"unable to create a cgroup under {target}: {exc}") from exc
        return child

    @staticmethod
    def _is_reusable(child: Path) -> bool:
        if not child.is_dir():
            return False
        procs = child / CGROUP_PROCS
        if not procs.exists() or not os.access(procs, os.W_OK):
            return False
        try:
            return not _read_text(procs).strip()
        except OSError:
            return False

    @staticmethod
    def _require_memory_interface(child: Path, target: Path) -> None:
        missing = [
            name for name in (CGROUP_MEMORY_MAX, CGROUP_MEMORY_CURRENT, CGROUP_PROCS) if not (child / name).exists()
        ]
        if missing:
            raise ValueError(f"memory controller not enabled for children of {target}: missing {', '.join(missing)}")

    def _enter(self, child: Path, oom_group: bool) -> None:
        _write_text(child / CGROUP_MEMORY_MAX, CGROUP_MAX_VALUE)
        if oom_group and (child / CGROUP_MEMORY_OOM_GROUP).exists():
            self._best_effort(child / CGROUP_MEMORY_OOM_GROUP, "1")
        if (child / CGROUP_MEMORY_SWAP_MAX).exists():
            self._best_effort(child / CGROUP_MEMORY_SWAP_MAX, "0")
        _write_text(child / CGROUP_PROCS, str(self._pid))
        self._migrated = True
        used = int(_read_text(child / CGROUP_MEMORY_CURRENT).strip())
        if used + CGROUP_USAGE_MARGIN_BYTES >= self.budget_bytes:
            raise ValueError(f"budget {self.budget_bytes // MIB} MiB is not above current usage {used // MIB} MiB")
        _write_text(child / CGROUP_MEMORY_MAX, str(self.budget_bytes))

    @staticmethod
    def _best_effort(path: Path, value: str) -> None:
        try:
            _write_text(path, value)
        except OSError:
            pass

    def _unwind(self) -> None:
        if self._migrated:
            try:
                _write_text(self._source_procs, str(self._pid))
            except OSError:
                pass
        if self._created:
            try:
                self.cgroup_path.rmdir()
            except OSError:
                pass

    def snapshot(self) -> MemorySnapshot:
        return MemorySnapshot(job_bytes=int(_read_text(self.cgroup_path / CGROUP_MEMORY_CURRENT).strip()))


def apply_address_space_limit(limit_mib: int) -> None:
    """Cap this process's address space; the last-resort per-worker bound on Linux."""
    if limit_mib < MINIMUM_ADDRESS_SPACE_LIMIT_MIB:
        raise ValueError(f"address-space limit must be at least {MINIMUM_ADDRESS_SPACE_LIMIT_MIB} MiB")
    import resource

    limit_bytes = limit_mib * MIB
    resource.setrlimit(resource.RLIMIT_AS, (limit_bytes, limit_bytes))


def kill_process_tree(pids: tuple[int, ...]) -> None:
    """Signal the probe's descendants-first snapshot, with the root last."""
    import signal

    for pid in pids:
        try:
            os.kill(pid, signal.SIGKILL)
        except OSError:
            pass


class ResidentMemoryWatchdog:
    """Kill a process tree that exceeds a resident-memory cap.

    ``RLIMIT_AS`` bounds address mappings rather than the memory a worker actually holds, so the
    degraded tier adds this sampler for the real cap.
    """

    def __init__(
        self,
        cap_bytes: int,
        *,
        probe_factory: Callable[..., ProcessTreeResidentMemoryProbe] = ProcessTreeResidentMemoryProbe,
        interval_seconds: float = DEFAULT_WATCHDOG_INTERVAL_SECONDS,
        kill: Callable[[tuple[int, ...]], None] = kill_process_tree,
    ) -> None:
        if cap_bytes < 1:
            raise ValueError("cap_bytes must be positive")
        self.cap_bytes = cap_bytes
        self.exceeded_bytes = 0
        self._probe_factory = probe_factory
        self._interval_seconds = interval_seconds
        self._kill = kill
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self, pid: int) -> None:
        self._thread = threading.Thread(target=self._watch, args=(pid,), daemon=True)
        self._thread.start()

    def stop(self) -> int:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=self._interval_seconds * 2)
            self._thread = None
        return self.exceeded_bytes

    def _watch(self, pid: int) -> None:
        probe = self._probe_factory(pid=pid)
        while not self._stop.wait(self._interval_seconds):
            pids, resident = probe.tree_pids_and_rss()
            if resident <= self.cap_bytes:
                continue
            self.exceeded_bytes = resident
            print(
                f"Resident memory watchdog: {resident // MIB} MiB exceeds the "
                f"{self.cap_bytes // MIB} MiB cap; killing {len(pids)} process(es)",
                flush=True,
            )
            self._kill(pids)
            return


def start_process_tree_limits(*, address_space_limit_mib: int, resident_cap_bytes: int) -> ResidentMemoryWatchdog:
    """Install both degraded-tier per-worker limits on this process and start the watchdog."""
    apply_address_space_limit(address_space_limit_mib)
    watchdog = ResidentMemoryWatchdog(resident_cap_bytes)
    watchdog.start(os.getpid())
    return watchdog


def build_posix_memory_controller(
    budget_bytes: int,
    *,
    cgroup_root: str | Path = DEFAULT_CGROUP_ROOT,
    proc_self_cgroup_path: str = PROC_SELF_CGROUP_PATH,
    pid: int | None = None,
    probe_factory: Callable[[], ProcessTreeResidentMemoryProbe] | None = None,
) -> ReservationMemoryController | CgroupV2MemoryController:
    """Return the strongest controller this host allows; never raise for environment reasons."""
    probe = probe_factory or ProcessTreeResidentMemoryProbe
    try:
        current = read_process_cgroup_path(proc_self_cgroup_path)
    except ValueError as exc:
        return ReservationMemoryController(budget_bytes, reason=str(exc), probe=probe())
    parent = str(PurePosixPath(current).parent)
    candidates = [candidate for candidate in (parent, current) if candidate not in ("", "/", ".")]
    reason = "no usable cgroup v2 parent"
    for target in dict.fromkeys(candidates):
        try:
            return CgroupV2MemoryController(
                budget_bytes,
                cgroup_root=cgroup_root,
                target_cgroup_path=target,
                source_cgroup_path=current,
                pid=pid,
            )
        except (OSError, ValueError) as exc:
            reason = f"{target}: {exc}"
    return ReservationMemoryController(budget_bytes, reason=reason, probe=probe())
