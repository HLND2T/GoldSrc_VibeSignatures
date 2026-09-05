"""Two-phase full-analysis batch classification, worker result contract, and bounded scheduling.

The coordinator consumes complete per-tag execution plans built by ``analysis_planner``,
classifies every node into a parallel (per-binary) or serial (cross-binary dependency
tail) set, and schedules one worker process per work item under bounded concurrency
and an aggregate memory admission gate.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable, Mapping, Protocol

PHASE_PARALLEL = "parallel"
PHASE_SERIAL = "serial"
RESULT_SCHEMA_VERSION = 1
WORKER_RESULT_KEYS = (
    "schema_version",
    "run_id",
    "work_item_id",
    "phase",
    "tag",
    "module",
    "platform",
    "binary_relative_path",
    "node_ids",
    "node_results",
    "status",
    "exit_code",
    "summary",
    "failure_reason",
)
WORKER_STATUS_SUCCEEDED = "succeeded"
WORKER_STATUS_FAILED = "failed"
NODE_TERMINAL_STATUSES = frozenset({"succeeded", "failed", "skipped", "aborted"})
WORKER_STATUSES = frozenset({WORKER_STATUS_SUCCEEDED, WORKER_STATUS_FAILED})
DEFAULT_WORKER_TIMEOUT_SECONDS = 4 * 3600.0
DEFAULT_ADMISSION_TIMEOUT_SECONDS = 300.0
SERIAL_REASON_MEMORY_LIMIT_EXCEEDED = "memory_limit_exceeded"


class BatchPlanError(ValueError):
    """Raised when a complete node DAG cannot be classified into two phases."""


class WorkerResultError(ValueError):
    """Raised when a worker result file violates the internal result contract."""


@dataclass(frozen=True)
class BinaryIdentity:
    tag: str
    module: str
    platform: str
    binary_relative_path: str


@dataclass(frozen=True)
class WorkItem:
    work_item_id: str
    phase: str
    binary: BinaryIdentity
    node_ids: tuple[str, ...]

    @property
    def log_prefix(self) -> str:
        return f"[{self.phase}/{self.binary.tag}/{self.binary.module}/{self.binary.platform}/{self.work_item_id}]"


@dataclass(frozen=True)
class BatchSchedule:
    parallel_items: tuple[WorkItem, ...]
    serial_items: tuple[WorkItem, ...]

    @property
    def all_items(self) -> tuple[WorkItem, ...]:
        return self.parallel_items + self.serial_items


def _node_binary_key(node) -> tuple[str, str]:
    return (node.module, node.platform)


def classify_tag_plan(
    tag: str,
    plan,
    binary_relative_paths: Mapping[tuple[str, str], str],
) -> tuple[list[WorkItem], list[WorkItem]]:
    """Classify one tag's complete node DAG into parallel work items and serial segments.

    ``plan.nodes`` must already be in stable topological order. Any dependency edge
    whose endpoints live on different binaries moves the target and its entire
    downstream closure into the serial set; the serial queue keeps node topological
    order and only merges consecutive nodes of the same binary into one segment.
    """
    nodes_by_id = {node.id: node for node in plan.nodes}
    if len(nodes_by_id) != len(plan.nodes):
        raise BatchPlanError(f"Plan for tag {tag} contains duplicate node IDs")
    for edge in plan.edges:
        if edge.source not in nodes_by_id or edge.target not in nodes_by_id:
            raise BatchPlanError(f"Plan for tag {tag} has an edge referencing unknown nodes: {edge}")
    downstream: dict[str, set[str]] = {node.id: set() for node in plan.nodes}
    for edge in plan.edges:
        downstream[edge.source].add(edge.target)

    serial_nodes: set[str] = set()
    for edge in plan.edges:
        if _node_binary_key(nodes_by_id[edge.source]) != _node_binary_key(nodes_by_id[edge.target]):
            serial_nodes.add(edge.target)
    changed = True
    while changed:
        changed = False
        for source in list(serial_nodes):
            for target in downstream[source]:
                if target not in serial_nodes:
                    serial_nodes.add(target)
                    changed = True

    parallel_nodes = [node for node in plan.nodes if node.id not in serial_nodes]
    for node in plan.nodes:
        if node.id in serial_nodes:
            for target in downstream[node.id]:
                if target not in serial_nodes:
                    raise BatchPlanError(f"Classification produced a serial -> parallel edge: {node.id} -> {target}")
    if len(parallel_nodes) + len(serial_nodes) != len(plan.nodes):
        raise BatchPlanError(f"Classification for tag {tag} does not cover every planned node")

    parallel_groups: dict[tuple[str, str], list[str]] = {}
    for node in parallel_nodes:
        parallel_groups.setdefault(_node_binary_key(node), []).append(node.id)

    parallel_items: list[WorkItem] = []
    for index, (binary_key, node_ids) in enumerate(parallel_groups.items()):
        parallel_items.append(
            WorkItem(
                work_item_id=f"{PHASE_PARALLEL}-{index:04d}",
                phase=PHASE_PARALLEL,
                binary=BinaryIdentity(
                    tag=tag,
                    module=binary_key[0],
                    platform=binary_key[1],
                    binary_relative_path=binary_relative_paths[binary_key],
                ),
                node_ids=tuple(node_ids),
            )
        )

    serial_items: list[WorkItem] = []
    segment: list[tuple[str, str]] = []
    segment_binary: tuple[str, str] | None = None

    def flush() -> None:
        nonlocal segment, segment_binary
        if segment:
            serial_items.append(
                WorkItem(
                    work_item_id=f"{PHASE_SERIAL}-{len(serial_items):04d}",
                    phase=PHASE_SERIAL,
                    binary=BinaryIdentity(
                        tag=tag,
                        module=segment_binary[0],
                        platform=segment_binary[1],
                        binary_relative_path=binary_relative_paths[segment_binary],
                    ),
                    node_ids=tuple(segment),
                )
            )
        segment = []
        segment_binary = None

    for node in plan.nodes:
        if node.id not in serial_nodes:
            continue
        node_binary = _node_binary_key(node)
        if segment_binary is not None and node_binary != segment_binary:
            flush()
        segment_binary = node_binary
        segment.append(node.id)
    flush()
    return parallel_items, serial_items


def build_batch_schedule(
    tag_plans: Iterable[tuple[str, object, Mapping[tuple[str, str], str]]],
) -> BatchSchedule:
    """Combine per-tag classifications into one schedule in tag declaration order."""
    parallel_items: list[WorkItem] = []
    serial_items: list[WorkItem] = []
    seen_binaries: set[BinaryIdentity] = set()
    for tag, plan, binary_relative_paths in tag_plans:
        tag_parallel, tag_serial = classify_tag_plan(tag, plan, binary_relative_paths)
        for item in tag_parallel + tag_serial:
            if item.binary in seen_binaries:
                raise BatchPlanError(f"Binary identity appears in multiple work items: {item.binary}")
            seen_binaries.add(item.binary)
        parallel_items.extend(tag_parallel)
        serial_items.extend(tag_serial)
    return BatchSchedule(parallel_items=tuple(parallel_items), serial_items=tuple(serial_items))


@dataclass(frozen=True)
class NodeResultEntry:
    node_id: str
    status: str
    reason: str | None


@dataclass(frozen=True)
class WorkerResult:
    run_id: str
    work_item: WorkItem
    status: str
    exit_code: int
    summary: dict[str, int]
    failure_reason: str | None
    node_results: tuple[NodeResultEntry, ...]


def _require_int(payload: dict, key: str) -> int:
    value = payload.get(key)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise WorkerResultError(f"{key} must be a non-negative integer")
    return value


def validate_worker_result(payload: object, work_item: WorkItem, *, run_id: str) -> WorkerResult:
    if not isinstance(payload, dict):
        raise WorkerResultError("worker result must be a JSON object")
    if tuple(sorted(payload)) != tuple(sorted(WORKER_RESULT_KEYS)):
        raise WorkerResultError("worker result key set does not match the contract")
    if payload["schema_version"] != RESULT_SCHEMA_VERSION:
        raise WorkerResultError("unsupported worker result schema_version")
    if payload["run_id"] != run_id:
        raise WorkerResultError("worker result run_id mismatch")
    if payload["work_item_id"] != work_item.work_item_id:
        raise WorkerResultError("worker result work_item_id mismatch")
    if payload["phase"] != work_item.phase:
        raise WorkerResultError("worker result phase mismatch")
    binary = work_item.binary
    if (
        payload["tag"] != binary.tag
        or payload["module"] != binary.module
        or payload["platform"] != binary.platform
        or payload["binary_relative_path"] != binary.binary_relative_path
    ):
        raise WorkerResultError("worker result binary identity mismatch")
    node_ids = payload["node_ids"]
    if not isinstance(node_ids, list) or not all(isinstance(item, str) for item in node_ids):
        raise WorkerResultError("worker result node_ids must be a list of strings")
    if tuple(node_ids) != work_item.node_ids:
        raise WorkerResultError("worker result node_ids do not exactly match the work item")
    status = payload["status"]
    if status not in WORKER_STATUSES:
        raise WorkerResultError(f"invalid worker status: {status!r}")
    failure_reason = payload["failure_reason"]
    if failure_reason is not None and not isinstance(failure_reason, str):
        raise WorkerResultError("failure_reason must be null or a string")
    summary = payload["summary"]
    if not isinstance(summary, dict) or tuple(sorted(summary)) != ("failed", "skipped", "successful"):
        raise WorkerResultError("summary must contain exactly successful/failed/skipped counts")
    summary_counts = {key: _require_int(summary, key) for key in ("successful", "failed", "skipped")}

    raw_node_results = payload["node_results"]
    if not isinstance(raw_node_results, list):
        raise WorkerResultError("node_results must be a list")
    entries: list[NodeResultEntry] = []
    for raw in raw_node_results:
        if not isinstance(raw, dict) or tuple(sorted(raw)) != ("node_id", "reason", "status"):
            raise WorkerResultError("each node result must contain exactly node_id/status/reason")
        if raw["status"] not in NODE_TERMINAL_STATUSES:
            raise WorkerResultError(f"invalid node terminal status: {raw['status']!r}")
        if raw["reason"] is not None and not isinstance(raw["reason"], str):
            raise WorkerResultError("node result reason must be null or a string")
        entries.append(NodeResultEntry(node_id=raw["node_id"], status=raw["status"], reason=raw["reason"]))
    if tuple(entry.node_id for entry in entries) != work_item.node_ids:
        raise WorkerResultError("node_results do not precisely cover the assigned node_ids")
    counted = {"successful": 0, "failed": 0, "skipped": 0}
    for entry in entries:
        if entry.status == "succeeded":
            counted["successful"] += 1
        elif entry.status == "skipped":
            counted["skipped"] += 1
        else:
            counted["failed"] += 1
    if counted != summary_counts:
        raise WorkerResultError("summary counts do not match node_results detail")
    if status == WORKER_STATUS_SUCCEEDED:
        if payload["exit_code"] != 0:
            raise WorkerResultError("succeeded worker result must report exit code zero")
        if summary_counts["failed"]:
            raise WorkerResultError("succeeded worker result cannot contain failed or aborted nodes")
        if failure_reason is not None:
            raise WorkerResultError("succeeded worker result cannot carry failure_reason")
    return WorkerResult(
        run_id=run_id,
        work_item=work_item,
        status=status,
        exit_code=payload["exit_code"],
        summary=summary_counts,
        failure_reason=failure_reason,
        node_results=tuple(entries),
    )


@dataclass
class BatchOutcome:
    succeeded: bool = False
    failure_reason: str | None = None
    successful: int = 0
    failed: int = 0
    skipped: int = 0
    aborted_node_ids: tuple[str, ...] = ()
    work_item_summaries: tuple[tuple[str, str], ...] = ()


class WorkerProcess(Protocol):
    def poll(self) -> int | None: ...

    def wait(self, timeout: float | None = None) -> int: ...

    def terminate(self) -> None: ...

    def kill(self) -> None: ...


class MemoryGateProtocol(Protocol):
    """Non-blocking admission interface; the scheduler polls workers between attempts."""

    def try_admit(self, worker_name: str) -> str | None:
        """Reserve one worker slot; return None when admitted, else the wait reason."""
        ...

    def worker_finished(self) -> None: ...


@dataclass
class _ActiveWorker:
    item: WorkItem
    process: WorkerProcess
    started_at: float
    result_path: Path | None = None


def _terminate_worker(worker: _ActiveWorker, *, grace_seconds: float, log) -> int:
    try:
        worker.process.terminate()
        worker.process.wait(timeout=grace_seconds)
    except Exception:  # noqa: BLE001 - escalate to kill after the grace period.
        try:
            worker.process.kill()
        except Exception as kill_error:  # noqa: BLE001
            log(f"{worker.item.log_prefix} worker kill failed: {kill_error}")
    try:
        return int(worker.process.wait(timeout=grace_seconds))
    except Exception:  # noqa: BLE001 - the exit code is diagnostic only after a hard kill.
        return -1


def _read_result_payload(result_path: Path) -> object:
    import json

    try:
        return json.loads(Path(result_path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise WorkerResultError(f"unable to read worker result file: {exc}") from exc


def run_batch(
    schedule: BatchSchedule,
    *,
    run_id: str,
    launch_worker: Callable[[WorkItem], tuple[WorkerProcess, Path]],
    max_concurrency: int,
    memory_gate: MemoryGateProtocol | None = None,
    skip_error: bool = False,
    worker_timeout_seconds: float = DEFAULT_WORKER_TIMEOUT_SECONDS,
    admission_timeout_seconds: float = DEFAULT_ADMISSION_TIMEOUT_SECONDS,
    terminate_grace_seconds: float = 30.0,
    poll_interval_seconds: float = 1.0,
    monotonic: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
    log: Callable[[str], None] = print,
    read_result_payload: Callable[[Path], object] = _read_result_payload,
) -> BatchOutcome:
    """Execute the two-phase schedule under bounded concurrency and one success barrier."""
    outcome = BatchOutcome()
    item_summaries: list[tuple[str, str]] = []
    aborted: list[str] = []

    def record_result(result: WorkerResult) -> None:
        outcome.successful += result.summary["successful"]
        outcome.skipped += result.summary["skipped"]
        outcome.failed += result.summary["failed"]
        item_summaries.append((result.work_item.work_item_id, result.status))

    def finish_worker(worker: _ActiveWorker, *, exit_code: int) -> WorkerResult | None:
        if memory_gate is not None:
            memory_gate.worker_finished()
        try:
            result = validate_worker_result(read_result_payload(worker.result_path), worker.item, run_id=run_id)
        except WorkerResultError as exc:
            outcome.failed += len(worker.item.node_ids)
            item_summaries.append((worker.item.work_item_id, WORKER_STATUS_FAILED))
            log(f"{worker.item.log_prefix} worker result contract violation: {exc}")
            return None
        if exit_code != result.exit_code:
            outcome.failed += len(worker.item.node_ids)
            item_summaries.append((worker.item.work_item_id, WORKER_STATUS_FAILED))
            log(
                f"{worker.item.log_prefix} worker exit code {exit_code} contradicts result exit code {result.exit_code}"
            )
            return None
        record_result(result)
        return result

    parallel_items = list(schedule.parallel_items)
    effective_parallel = max(1, min(max_concurrency, len(parallel_items))) if parallel_items else 0
    log(
        f"Batch coordinator: {len(parallel_items)} parallel item(s), {len(schedule.serial_items)} serial "
        f"segment(s); effective concurrency {effective_parallel}; skip_error={skip_error}"
    )

    active: list[_ActiveWorker] = []
    pending = parallel_items
    stop_admission = False
    parallel_failed = False
    failure_reason: str | None = None
    admission_wait_started: dict[str, float] = {}

    def _stop_for_gate_failure(item: WorkItem, reason: str, detail: str) -> None:
        nonlocal stop_admission, parallel_failed, failure_reason
        stop_admission = True
        parallel_failed = True
        failure_reason = reason
        log(f"{item.log_prefix} {detail}")

    while pending or active:
        while not stop_admission and pending and len(active) < effective_parallel:
            item = pending[0]
            if memory_gate is not None:
                try:
                    wait_reason = memory_gate.try_admit(item.work_item_id)
                except Exception as exc:  # noqa: BLE001 - memory gate failures fail the batch.
                    _stop_for_gate_failure(item, "memory_gate_error", f"memory gate failure: {exc}")
                    break
                if wait_reason is not None:
                    now = monotonic()
                    started = admission_wait_started.setdefault(item.work_item_id, now)
                    if now - started >= admission_timeout_seconds:
                        admission_wait_started.pop(item.work_item_id, None)
                        _stop_for_gate_failure(
                            item,
                            "memory_admission_timeout",
                            f"memory admission timed out after {admission_timeout_seconds:g}s; last reason: {wait_reason}",
                        )
                        break
                    break  # retry admission after polling active workers
                admission_wait_started.pop(item.work_item_id, None)
            try:
                process, result_path = launch_worker(item)
            except Exception as exc:  # noqa: BLE001 - launch failures count as worker failures.
                pending.pop(0)
                outcome.failed += len(item.node_ids)
                item_summaries.append((item.work_item_id, WORKER_STATUS_FAILED))
                parallel_failed = True
                failure_reason = failure_reason or "worker_launch_failed"
                log(f"{item.log_prefix} worker launch failed: {exc}")
                if not skip_error:
                    stop_admission = True
                if memory_gate is not None:
                    memory_gate.worker_finished()
                continue
            pending.pop(0)
            worker = _ActiveWorker(item=item, process=process, started_at=monotonic())
            worker.result_path = result_path
            active.append(worker)
            log(f"{item.log_prefix} worker admitted (pid {getattr(process, 'pid', '?')})")
        if not active:
            if stop_admission or not pending:
                break
            sleep(poll_interval_seconds)
            continue
        sleep(poll_interval_seconds)
        for worker in list(active):
            exit_code = worker.process.poll()
            if exit_code is None:
                if monotonic() - worker.started_at > worker_timeout_seconds:
                    log(f"{worker.item.log_prefix} worker timeout after {worker_timeout_seconds:g}s")
                    exit_code = _terminate_worker(worker, grace_seconds=terminate_grace_seconds, log=log)
                    outcome.failed += len(worker.item.node_ids)
                    item_summaries.append((worker.item.work_item_id, WORKER_STATUS_FAILED))
                    active.remove(worker)
                    if memory_gate is not None:
                        memory_gate.worker_finished()
                    parallel_failed = True
                    failure_reason = failure_reason or "worker_timeout"
                    if not skip_error:
                        stop_admission = True
                continue
            active.remove(worker)
            result = finish_worker(worker, exit_code=exit_code)
            if result is None or result.status != WORKER_STATUS_SUCCEEDED:
                parallel_failed = True
                failure_reason = failure_reason or "worker_failed"
                if not skip_error:
                    stop_admission = True

    for item in pending:
        aborted.extend(f"{item.binary.tag}:{node_id}" for node_id in item.node_ids)

    # Success barrier: serial segments start only after every parallel worker exited.
    if active:
        log("Batch coordinator barrier violation: parallel workers still active")
    serial_blocked = parallel_failed or bool(active)
    if serial_blocked and schedule.serial_items:
        for item in schedule.serial_items:
            aborted.extend(f"{item.binary.tag}:{node_id}" for node_id in item.node_ids)
        log(
            "Batch coordinator: serial phase blocked by parallel failure "
            f"({failure_reason or 'worker_failed'}); aborting {len(schedule.serial_items)} segment(s)"
        )
    elif schedule.serial_items:
        for item in schedule.serial_items:
            if memory_gate is not None:
                admitted_at = monotonic()
                while True:
                    try:
                        wait_reason = memory_gate.try_admit(item.work_item_id)
                    except Exception as exc:  # noqa: BLE001
                        failure_reason = failure_reason or "memory_gate_error"
                        log(f"{item.log_prefix} serial memory gate failure: {exc}")
                        wait_reason = "error"
                    if wait_reason is None:
                        break
                    if monotonic() - admitted_at >= admission_timeout_seconds or wait_reason == "error":
                        outcome.failed += len(item.node_ids)
                        item_summaries.append((item.work_item_id, WORKER_STATUS_FAILED))
                        failure_reason = failure_reason or "memory_admission_timeout"
                        log(f"{item.log_prefix} serial memory admission failed; last reason: {wait_reason}")
                        for remaining in schedule.serial_items[schedule.serial_items.index(item) + 1 :]:
                            aborted.extend(f"{remaining.binary.tag}:{nid}" for nid in remaining.node_ids)
                        item = None
                        break
                    sleep(poll_interval_seconds)
                if item is None:
                    break
            try:
                process, result_path = launch_worker(item)
            except Exception as exc:  # noqa: BLE001
                outcome.failed += len(item.node_ids)
                item_summaries.append((item.work_item_id, WORKER_STATUS_FAILED))
                failure_reason = failure_reason or "worker_launch_failed"
                log(f"{item.log_prefix} serial worker launch failed: {exc}")
                if memory_gate is not None:
                    memory_gate.worker_finished()
                break
            worker = _ActiveWorker(item=item, process=process, started_at=monotonic())
            worker.result_path = result_path
            log(f"{item.log_prefix} serial worker admitted (pid {getattr(process, 'pid', '?')})")
            try:
                exit_code = worker.process.wait(timeout=worker_timeout_seconds)
            except Exception:  # noqa: BLE001 - treat wait timeouts as bounded worker timeouts.
                exit_code = _terminate_worker(worker, grace_seconds=terminate_grace_seconds, log=log)
                outcome.failed += len(item.node_ids)
                item_summaries.append((item.work_item_id, WORKER_STATUS_FAILED))
                failure_reason = failure_reason or "worker_timeout"
                if memory_gate is not None:
                    memory_gate.worker_finished()
                break
            result = finish_worker(worker, exit_code=exit_code)
            if result is None or result.status != WORKER_STATUS_SUCCEEDED:
                failure_reason = failure_reason or "worker_failed"
                index = schedule.serial_items.index(item)
                for remaining in schedule.serial_items[index + 1 :]:
                    aborted.extend(f"{remaining.binary.tag}:{nid}" for nid in remaining.node_ids)
                break

    if aborted:
        outcome.failed += len(aborted)
    outcome.aborted_node_ids = tuple(aborted)
    outcome.work_item_summaries = tuple(item_summaries)
    outcome.succeeded = outcome.failed == 0 and outcome.aborted_node_ids == ()
    outcome.failure_reason = failure_reason
    return outcome


@dataclass(frozen=True)
class BatchRunRequest:
    """Invocation-scoped work item request handed to one internal worker process."""

    run_id: str
    work_item_id: str
    phase: str
    tag: str
    module: str
    platform: str
    binary_relative_path: str
    node_ids: tuple[str, ...]
    options: dict = field(default_factory=dict)

    @classmethod
    def from_work_item(cls, item: WorkItem, *, options: Mapping[str, object] | None = None) -> "BatchRunRequest":
        binary = item.binary
        return cls(
            run_id="",
            work_item_id=item.work_item_id,
            phase=item.phase,
            tag=binary.tag,
            module=binary.module,
            platform=binary.platform,
            binary_relative_path=binary.binary_relative_path,
            node_ids=item.node_ids,
            options=dict(options or {}),
        )
