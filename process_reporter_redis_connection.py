"""Low-level Redis commands used by the process reporter write model."""

import json
import os
import socket
import uuid
from dataclasses import dataclass
from typing import Any

from redis import Redis
from redis.exceptions import RedisError

from process_reporter_redis_scripts import (
    FINALIZE_RUN_LUA,
    INITIALIZE_RUN_LUA,
    RUN_TRANSITION_LUA,
    TASK_TRANSITION_LUA,
)


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


@dataclass(frozen=True)
class RedisKeyBuilder:
    """Build every Redis key from one normalized namespace prefix."""

    prefix: str

    def __post_init__(self) -> None:
        normalized = self.prefix.strip().strip(":")
        if not normalized:
            raise ValueError("Redis key prefix must not be empty")
        object.__setattr__(self, "prefix", normalized)

    @property
    def runs(self) -> str:
        return f"{self.prefix}:runs"

    @property
    def running(self) -> str:
        return f"{self.prefix}:running"

    @property
    def run_queue(self) -> str:
        return f"{self.prefix}:run-queue"

    @property
    def scheduler_lease(self) -> str:
        return f"{self.prefix}:scheduler-lease"

    def run_meta(self, run_id: str) -> str:
        return f"{self.prefix}:run:{run_id}:meta"

    def graph(self, run_id: str) -> str:
        return f"{self.prefix}:run:{run_id}:graph"

    def task_status(self, run_id: str) -> str:
        return f"{self.prefix}:run:{run_id}:skill-status"

    def task_data(self, run_id: str) -> str:
        return f"{self.prefix}:run:{run_id}:skill-data"

    def events(self, run_id: str) -> str:
        return f"{self.prefix}:run:{run_id}:events"

    def heartbeat(self, run_id: str) -> str:
        return f"{self.prefix}:run:{run_id}:heartbeat"


class RedisWriteConnection:
    """Own a redis-py client and execute the registered Lua scripts."""

    def __init__(
        self,
        redis_url: str,
        prefix: str,
        heartbeat_ttl: int,
        stream_maxlen: int,
        worker_id: str | None,
    ):
        self.redis_url = redis_url
        self.keys = RedisKeyBuilder(prefix)
        self.heartbeat_ttl = heartbeat_ttl
        self.stream_maxlen = stream_maxlen
        self.worker_id = worker_id or f"{socket.gethostname()}:{os.getpid()}:{uuid.uuid4().hex[:8]}"
        self._client = None
        self._scripts = {}

    def initialize_run(
        self,
        run_id: str,
        created_at: str,
        created_score: float,
        plan: dict[str, Any],
        tasks: dict[str, dict[str, Any]],
        metadata: dict[str, str],
        total: int,
    ):
        task_payload = [{"id": task_id, "data": data} for task_id, data in tasks.items()]
        return self._script("initialize")(
            keys=[
                self.keys.runs,
                self.keys.running,
                self.keys.run_meta(run_id),
                self.keys.graph(run_id),
                self.keys.task_status(run_id),
                self.keys.task_data(run_id),
                self.keys.events(run_id),
            ],
            args=[
                run_id,
                created_at,
                created_score,
                _json(plan),
                _json(task_payload),
                _json(metadata),
                total,
                self.stream_maxlen,
            ],
        )

    def task_transition(
        self,
        run_id: str,
        task_id: str,
        data: dict[str, Any],
        event_type: str,
        counted: bool,
        location: tuple[str, str, str],
        snapshot: bool,
    ):
        stage_id, job_id, skill_id = location
        return self._script("task")(
            keys=[
                self.keys.task_status(run_id),
                self.keys.task_data(run_id),
                self.keys.run_meta(run_id),
                self.keys.events(run_id),
            ],
            args=[
                task_id,
                data["revision"],
                data["status"],
                data["phase"] or "",
                data["reason"] or "",
                event_type,
                data["updated_at"],
                _json(data),
                "1" if counted else "0",
                stage_id,
                job_id,
                skill_id,
                self.stream_maxlen,
                "1" if snapshot else "0",
            ],
        )

    def run_transition(self, run_id: str, data: dict[str, Any], snapshot: bool):
        return self._script("run")(
            keys=[self.keys.run_meta(run_id), self.keys.running, self.keys.events(run_id)],
            args=[
                data["revision"],
                data["status"],
                "run.status_changed",
                data["updated_at"],
                _json(data),
                run_id,
                self.stream_maxlen,
                "1" if snapshot else "0",
            ],
        )

    def finalize_run(self, run_id: str, status: str, finalized_at: str, summary: dict[str, int]):
        return self._script("finalize")(
            keys=[self.keys.run_meta(run_id), self.keys.running],
            args=[status, finalized_at, _json(summary), run_id],
        )

    def heartbeat(self, run_id: str) -> None:
        self._get_client().set(self.keys.heartbeat(run_id), self.worker_id, ex=self.heartbeat_ttl)

    def close(self) -> None:
        client, self._client = self._client, None
        self._scripts = {}
        if client is not None:
            try:
                client.close()
            except RedisError:
                pass

    def _script(self, name: str):
        self._get_client()
        return self._scripts[name]

    def _get_client(self):
        if self._client is None:
            self._client = Redis.from_url(
                self.redis_url,
                decode_responses=True,
                socket_connect_timeout=1.0,
                socket_timeout=2.0,
                health_check_interval=15,
            )
            self._client.ping()
            self._scripts = {
                "initialize": self._client.register_script(INITIALIZE_RUN_LUA),
                "task": self._client.register_script(TASK_TRANSITION_LUA),
                "run": self._client.register_script(RUN_TRANSITION_LUA),
                "finalize": self._client.register_script(FINALIZE_RUN_LUA),
            }
        return self._client
