"""Pure normalization helpers for the Redis process status read model."""

import json
from typing import Any

from process_reporter import ProcessPhase, RunStatus, TaskStatus


class RedisStatusDataError(RuntimeError):
    """Raised when persisted status data violates the expected contract."""


def json_object(value: str | None, label: str) -> dict[str, Any] | None:
    if value is None:
        return None
    try:
        decoded = json.loads(value)
    except (TypeError, json.JSONDecodeError) as exc:
        raise RedisStatusDataError(f"Invalid {label} JSON") from exc
    if not isinstance(decoded, dict):
        raise RedisStatusDataError(f"Invalid {label} object")
    return decoded


def run_view(run_id: str, meta: dict[str, str], heartbeat_alive: bool) -> dict[str, Any]:
    try:
        status = RunStatus(meta["status"]).value
    except (KeyError, ValueError) as exc:
        raise RedisStatusDataError("Invalid run status") from exc
    is_stale = status == RunStatus.STALE.value or (status == RunStatus.RUNNING.value and not heartbeat_alive)
    return {
        "run_id": run_id,
        "status": status,
        "effective_status": RunStatus.STALE.value if is_stale else status,
        "is_stale": is_stale,
        "heartbeat_alive": heartbeat_alive,
        "gamever": _optional(meta.get("gamever")),
        "agent": _optional(meta.get("agent")),
        "created_at": _optional(meta.get("created_at")),
        "started_at": _optional(meta.get("started_at")),
        "updated_at": _optional(meta.get("updated_at")),
        "finished_at": _optional(meta.get("finished_at")),
        "current_stage_id": _optional(meta.get("current_stage_id")),
        "current_job_id": _optional(meta.get("current_job_id")),
        "current_skill_id": _optional(meta.get("current_skill_id")),
        "last_event_id": meta.get("last_event_id") or "0-0",
        "error_summary": _optional(meta.get("error_summary")),
        "progress": _progress(meta),
    }


def task_views(graph: dict[str, Any] | None, raw_tasks: dict[str, str]) -> list[dict[str, Any]]:
    descriptors, ordered_ids = _task_descriptors(graph)
    ordered_ids.extend(sorted(set(raw_tasks) - set(ordered_ids)))
    return [
        _task_view(task_id, raw_tasks[task_id], descriptors.get(task_id, {}))
        for task_id in ordered_ids
        if task_id in raw_tasks
    ]


def event_view(run_id: str, event_id: str, fields: dict[str, str]) -> dict[str, Any]:
    return {
        "id": str(event_id),
        "type": fields.get("type", "message"),
        "run_id": run_id,
        "task_id": _optional(fields.get("task_id")),
        "status": _optional(fields.get("status")),
        "phase": _optional(fields.get("phase")),
        "reason": _optional(fields.get("reason")),
        "occurred_at": _optional(fields.get("occurred_at")),
        "revision": _integer(fields.get("revision")),
        "data": json_object(fields.get("data") or "{}", "event data") or {},
    }


def _task_descriptors(graph: dict[str, Any] | None):
    descriptors = {}
    ordered_ids = []
    stage_descriptions = {stage["id"]: _optional(stage.get("description")) for stage in (graph or {}).get("stages", [])}
    for job in (graph or {}).get("jobs", []):
        task_id = job["id"]
        descriptors[task_id] = {
            "task_type": "job",
            "name": task_id,
            "description": stage_descriptions.get(job.get("stage_id")),
            "stage_id": job.get("stage_id"),
            "job_id": task_id,
        }
        ordered_ids.append(task_id)
    for node in (graph or {}).get("nodes", []):
        task_id = node["id"]
        descriptors[task_id] = {
            "task_type": node.get("node_type", "skill"),
            "name": node.get("name", task_id),
            "description": _optional(node.get("description")),
            "stage_id": node.get("stage_id"),
            "job_id": node.get("job_id"),
        }
        ordered_ids.append(task_id)
    return descriptors, ordered_ids


def _task_view(task_id: str, raw: str, descriptor: dict[str, Any]) -> dict[str, Any]:
    data = json_object(raw, f"task {task_id}") or {}
    try:
        status = TaskStatus(data["status"]).value
        phase = ProcessPhase(data["phase"]).value
    except (KeyError, ValueError) as exc:
        raise RedisStatusDataError("Invalid task status") from exc
    return {
        "task_id": task_id,
        "task_type": descriptor.get("task_type", data.get("task_type", "skill")),
        "name": descriptor.get("name", task_id),
        "description": descriptor.get("description"),
        "stage_id": descriptor.get("stage_id"),
        "job_id": descriptor.get("job_id"),
        "status": status,
        "phase": phase,
        "reason": _optional(data.get("reason")),
        "attempt": data.get("attempt"),
        "max_attempts": data.get("max_attempts"),
        "started_at": _optional(data.get("started_at")),
        "updated_at": _optional(data.get("updated_at")),
        "finished_at": _optional(data.get("finished_at")),
        "message": _optional(data.get("message")),
        "error": _optional(data.get("error")),
        "payload": data.get("payload") or {},
        "event_type": data.get("event_type", "task.status_changed"),
        "revision": _integer(data.get("revision")),
    }


def _progress(meta: dict[str, str]) -> dict[str, int | float]:
    names = ("total", "pending", "running", "succeeded", "failed", "skipped", "aborted")
    counts = {name: _integer(meta.get(name)) for name in names}
    completed = sum(counts[name] for name in ("succeeded", "failed", "skipped", "aborted"))
    percent = round(completed / counts["total"] * 100, 2) if counts["total"] else 0.0
    return {**counts, "completed": completed, "percent": percent}


def _optional(value: Any) -> Any:
    return value if value not in (None, "") else None


def _integer(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default
