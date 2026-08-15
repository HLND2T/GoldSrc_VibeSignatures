"""Reconnect-safe Redis write model for Analyzer process reporting."""

import threading
import time
from datetime import datetime, timezone
from typing import Any, Callable

from redis.exceptions import RedisError

from process_reporter import ProcessEvent, ProcessEventType, RunStatus, generate_run_id
from process_reporter_redis_connection import RedisKeyBuilder as RedisKeyBuilder
from process_reporter_redis_connection import RedisWriteConnection
from process_reporter_redis_state import (
    apply_run_event,
    apply_task_event,
    build_task_snapshots,
    enum_value,
    initial_run_state,
)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


_RUN_METADATA_FIELDS = {"gamever", "agent", "config_path"}


class RedisProcessReporter:
    """Persist run snapshots and events while tolerating temporary Redis loss."""

    def __init__(
        self,
        redis_url: str,
        prefix: str,
        *,
        run_metadata: dict[str, Any] | None = None,
        heartbeat_ttl: int = 30,
        heartbeat_interval: float = 10.0,
        stream_maxlen: int = 10_000,
        worker_id: str | None = None,
        warning_callback: Callable[[str], None] = print,
    ):
        if heartbeat_ttl <= 0 or heartbeat_interval <= 0 or stream_maxlen <= 0:
            raise ValueError("Heartbeat and stream settings must be positive")
        self.redis_url = redis_url
        self.run_metadata = {
            key: str(value)
            for key, value in (run_metadata or {}).items()
            if key in _RUN_METADATA_FIELDS and value is not None
        }
        self.heartbeat_ttl = heartbeat_ttl
        self.heartbeat_interval = heartbeat_interval
        self._warning_callback = warning_callback
        self._connection = RedisWriteConnection(
            redis_url,
            prefix,
            heartbeat_ttl,
            stream_maxlen,
            worker_id,
        )
        self.keys = self._connection.keys
        self.worker_id = self._connection.worker_id
        self._lock = threading.RLock()
        self._stop_event = threading.Event()
        self._heartbeat_thread = None
        self._run_id = None
        self._plan = None
        self._tasks = {}
        self._locations = {}
        self._counted_task_ids = set()
        self._run_state = None
        self._created_at = None
        self._created_score = None
        self._final_summary = None
        self._final_status = None
        self._finalized_at = None
        self._dirty = False
        self._offline_warned = False
        self._last_result_invalid = False

    def initialize_run(self, plan: dict[str, Any], run_id: str | None = None) -> str:
        with self._lock:
            self._run_id = run_id or generate_run_id()
            self._plan = plan
            self._created_at = _utc_now()
            self._created_score = time.time()
            self._tasks, self._locations, self._counted_task_ids = build_task_snapshots(plan, self._created_at)
            self._run_state = initial_run_state(self._created_at)
            self._dirty = True
            self._try_resync_locked()
            self._start_heartbeat_locked()
            return self._run_id

    def emit(self, event: ProcessEvent) -> None:
        with self._lock:
            self._require_run_locked(event.run_id)
            if self._dirty:
                self._try_resync_locked()
            if event.event_type == ProcessEventType.RUN_STATUS_CHANGED:
                self._emit_run_locked(event)
            elif event.event_type in {ProcessEventType.TASK_STATUS_CHANGED, ProcessEventType.SKILL_PROGRESS}:
                self._emit_task_locked(event)
            elif event.event_type == ProcessEventType.HEARTBEAT:
                self._write_or_defer_locked(self._write_heartbeat_locked)

    def heartbeat(self, run_id: str) -> None:
        with self._lock:
            self._require_run_locked(run_id)
            if self._dirty and not self._try_resync_locked():
                return
            self._write_or_defer_locked(self._write_heartbeat_locked)

    def finalize_run(self, run_id: str, status: RunStatus, summary: dict[str, int]) -> None:
        with self._lock:
            self._require_run_locked(run_id)
            self._final_status = enum_value(status)
            self._final_summary = dict(summary)
            self._finalized_at = _utc_now()
            if self._dirty and not self._try_resync_locked():
                return
            self._write_or_defer_locked(self._write_finalize_locked)

    def flush(self) -> None:
        with self._lock:
            if self._run_id and self._dirty:
                self._try_resync_locked()

    def close(self) -> None:
        self._stop_event.set()
        thread = self._heartbeat_thread
        if thread and thread is not threading.current_thread():
            thread.join(timeout=1.0)
        self.flush()
        with self._lock:
            self._connection.close()

    def _emit_run_locked(self, event: ProcessEvent) -> None:
        previous = self._run_state
        self._run_state = apply_run_event(previous, event)
        if self._dirty:
            return

        def writer():
            return self._write_run_locked(snapshot=False)

        if not self._write_or_defer_locked(writer):
            return
        if self._last_result_invalid:
            self._run_state = previous

    def _emit_task_locked(self, event: ProcessEvent) -> None:
        if not event.task_id:
            self._warn("Warning: Redis process reporter ignored a task event without task_id")
            return
        current = self._tasks.get(event.task_id)
        if current is None:
            current = build_task_snapshots({"jobs": [{"id": event.task_id}]}, event.occurred_at)[0][event.task_id]
            self._tasks[event.task_id] = current
            self._locations[event.task_id] = ("", "", event.task_id)
        previous = current
        self._tasks[event.task_id] = apply_task_event(current, event)
        if self._dirty:
            return

        def writer():
            return self._write_task_locked(event.task_id, event.event_type.value, snapshot=False)

        if not self._write_or_defer_locked(writer):
            return
        if self._last_result_invalid:
            self._tasks[event.task_id] = previous

    def _try_resync_locked(self) -> bool:
        try:
            self._initialize_remote_locked()
            if self._run_state["revision"]:
                if not self._transition_accepted_locked(self._write_run_locked(snapshot=True)):
                    return False
            for task_id, snapshot in self._tasks.items():
                if snapshot["revision"]:
                    result = self._write_task_locked(task_id, snapshot["event_type"], snapshot=True)
                    if not self._transition_accepted_locked(result):
                        return False
            if self._final_summary is not None:
                self._write_finalize_locked()
            self._write_heartbeat_locked()
        except RedisError as exc:
            self._mark_offline_locked(exc)
            return False
        self._dirty = False
        if self._offline_warned:
            self._warn("Redis process reporter reconnected and resynchronized")
            self._offline_warned = False
        return True

    def _write_or_defer_locked(self, writer) -> bool:
        self._last_result_invalid = False
        try:
            result = writer()
        except RedisError as exc:
            self._mark_offline_locked(exc)
            return False
        if not self._transition_accepted_locked(result):
            self._last_result_invalid = True
        return True

    def _transition_accepted_locked(self, result) -> bool:
        if isinstance(result, (list, tuple)) and int(result[0]) < 0:
            self._warn(f"Warning: Redis process reporter rejected an invalid transition: {result}")
            return False
        return True

    def _initialize_remote_locked(self) -> None:
        self._connection.initialize_run(
            self._run_id,
            self._created_at,
            self._created_score,
            self._plan,
            self._tasks,
            self.run_metadata,
            len(self._counted_task_ids),
        )

    def _write_task_locked(self, task_id: str, event_type: str, *, snapshot: bool):
        data = self._tasks[task_id]
        return self._connection.task_transition(
            self._run_id,
            task_id,
            data,
            event_type,
            task_id in self._counted_task_ids,
            self._locations.get(task_id, ("", "", "")),
            snapshot,
        )

    def _write_run_locked(self, *, snapshot: bool):
        data = self._run_state
        return self._connection.run_transition(self._run_id, data, snapshot)

    def _write_finalize_locked(self):
        return self._connection.finalize_run(
            self._run_id,
            self._final_status,
            self._finalized_at,
            self._final_summary,
        )

    def _write_heartbeat_locked(self) -> None:
        self._connection.heartbeat(self._run_id)

    def _mark_offline_locked(self, exc: Exception) -> None:
        self._dirty = True
        self._connection.close()
        if not self._offline_warned:
            self._warn(f"Warning: Redis process reporter unavailable; snapshot queued for resync: {exc}")
            self._offline_warned = True

    def _warn(self, message: str) -> None:
        try:
            self._warning_callback(message)
        except Exception:
            pass

    def _require_run_locked(self, run_id: str) -> None:
        if self._run_id is None:
            raise RuntimeError("Redis process reporter has not initialized a run")
        if run_id != self._run_id:
            raise ValueError(f"Event run_id {run_id!r} does not match initialized run {self._run_id!r}")

    def _start_heartbeat_locked(self) -> None:
        if self._heartbeat_thread is not None:
            return
        self._heartbeat_thread = threading.Thread(
            target=self._heartbeat_loop,
            name=f"redis-heartbeat-{self._run_id}",
            daemon=True,
        )
        self._heartbeat_thread.start()

    def _heartbeat_loop(self) -> None:
        while not self._stop_event.wait(self.heartbeat_interval):
            try:
                self.heartbeat(self._run_id)
            except Exception as exc:
                self._warn(f"Warning: Redis heartbeat failed: {exc}")
