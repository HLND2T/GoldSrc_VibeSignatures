"""Local snapshot helpers for reconnect-safe Redis process reporting."""

from copy import deepcopy
from enum import Enum
from typing import Any

from process_reporter import ProcessEvent

_TERMINAL_TASK_STATUSES = {"succeeded", "failed", "skipped", "aborted"}


def enum_value(value: Any) -> Any:
    return value.value if isinstance(value, Enum) else value


def initial_task_state(task_type: str, updated_at: str) -> dict[str, Any]:
    return {
        "status": "pending",
        "phase": "preflight",
        "reason": None,
        "attempt": None,
        "max_attempts": None,
        "started_at": None,
        "updated_at": updated_at,
        "finished_at": None,
        "message": None,
        "error": None,
        "payload": {},
        "event_type": "task.status_changed",
        "revision": 0,
        "task_type": task_type,
    }


def build_task_snapshots(plan: dict[str, Any], updated_at: str):
    snapshots = {}
    locations = {}
    counted_task_ids = set()
    for job in plan.get("jobs", []):
        task_id = job["id"]
        snapshots[task_id] = initial_task_state("job", updated_at)
        locations[task_id] = (job.get("stage_id", ""), task_id, "")
    for node in plan.get("nodes", []):
        task_id = node["id"]
        snapshots[task_id] = initial_task_state(node.get("node_type", "skill"), updated_at)
        locations[task_id] = (node.get("stage_id", ""), node.get("job_id", ""), task_id)
        counted_task_ids.add(task_id)
    return snapshots, locations, counted_task_ids


def apply_task_event(current: dict[str, Any], event: ProcessEvent) -> dict[str, Any]:
    snapshot = deepcopy(current)
    status = enum_value(event.status) or snapshot["status"]
    phase = enum_value(event.phase) or snapshot["phase"]
    reason = enum_value(event.reason)
    snapshot.update(
        status=status,
        phase=phase,
        reason=reason,
        message=event.message,
        error=event.error,
        payload=deepcopy(event.payload),
        event_type=event.event_type.value,
        updated_at=event.occurred_at,
        revision=snapshot["revision"] + 1,
    )
    if "attempt" in event.payload:
        snapshot["attempt"] = event.payload["attempt"]
    if "max_attempts" in event.payload:
        snapshot["max_attempts"] = event.payload["max_attempts"]
    if status == "running" and snapshot["started_at"] is None:
        snapshot["started_at"] = event.occurred_at
    if status in _TERMINAL_TASK_STATUSES:
        snapshot["finished_at"] = event.occurred_at
    return snapshot


def initial_run_state(updated_at: str) -> dict[str, Any]:
    return {
        "status": "starting",
        "message": None,
        "updated_at": updated_at,
        "revision": 0,
    }


def apply_run_event(current: dict[str, Any], event: ProcessEvent) -> dict[str, Any]:
    snapshot = deepcopy(current)
    snapshot.update(
        status=enum_value(event.status) or snapshot["status"],
        message=event.message,
        updated_at=event.occurred_at,
        revision=snapshot["revision"] + 1,
    )
    return snapshot
