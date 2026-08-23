import json
import os
import re
import socket
import subprocess
import sys
import threading
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from redis import Redis
from redis.exceptions import ResponseError

from analysis_config import AnalysisConfigError, resolve_analysis_config, validated_tag
from process_reporter import RunStatus, generate_run_id
from process_reporter_redis_connection import RedisKeyBuilder
from process_reporter_redis_scripts import (
    RELEASE_SCHEDULER_LEASE_LUA,
    RENEW_SCHEDULER_LEASE_LUA,
    SCHEDULER_RUN_TRANSITION_LUA,
    SUBMIT_RUN_LUA,
)

_TERMINAL_STATUSES = {RunStatus.SUCCEEDED.value, RunStatus.FAILED.value, RunStatus.ABORTED.value}
_ALLOWED_AGENTS = {"claude", "claude.cmd", "codex", "codex.cmd", "opencode", "opencode.cmd"}
_IDENTIFIER = re.compile(r"^[A-Za-z0-9_.:-]+$")


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _validate_identifier(value: str, label: str, *, max_length: int = 160) -> str:
    normalized = str(value).strip()
    if not normalized or len(normalized) > max_length or not _IDENTIFIER.fullmatch(normalized):
        raise ValueError(f"Invalid {label}: {value!r}")
    return normalized


def _validate_csv(value: str, label: str, allowed: set[str] | None = None) -> str:
    normalized = str(value).strip()
    if normalized == "*" and label == "modules":
        return normalized
    items = [item.strip() for item in normalized.split(",") if item.strip()]
    if not items:
        raise ValueError(f"{label} must contain at least one value")
    for item in items:
        _validate_identifier(item, label)
        if allowed is not None and item not in allowed:
            raise ValueError(f"Unsupported {label} value: {item}")
    return ",".join(items)


@dataclass(frozen=True)
class RunRequest:
    run_id: str
    gamever: str
    platforms: str = "windows,linux"
    modules: str = "*"
    skill_filter: str | None = None
    agent: str = "claude"
    created_at: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "run_id", _validate_identifier(self.run_id, "run_id"))
        try:
            gamever = validated_tag(self.gamever)
        except AnalysisConfigError as exc:
            raise ValueError(str(exc)) from exc
        object.__setattr__(self, "gamever", gamever)
        object.__setattr__(self, "platforms", _validate_csv(self.platforms, "platforms", {"windows", "linux"}))
        object.__setattr__(self, "modules", _validate_csv(self.modules, "modules"))
        if self.skill_filter is not None:
            object.__setattr__(self, "skill_filter", _validate_identifier(self.skill_filter, "skill_filter"))
        normalized_agent = str(self.agent).strip().lower()
        if normalized_agent not in _ALLOWED_AGENTS:
            raise ValueError(f"Unsupported agent: {self.agent}")
        object.__setattr__(self, "agent", normalized_agent)
        object.__setattr__(self, "created_at", self.created_at or _utc_now())

    @classmethod
    def create(cls, gamever: str, **kwargs) -> "RunRequest":
        return cls(run_id=kwargs.pop("run_id", None) or generate_run_id(), gamever=gamever, **kwargs)

    @classmethod
    def from_stream(cls, fields: dict[str, str]) -> "RunRequest":
        return cls(
            run_id=fields["run_id"],
            gamever=fields["gamever"],
            platforms=fields["platforms"],
            modules=fields["modules"],
            skill_filter=fields.get("skill_filter") or None,
            agent=fields["agent"],
            created_at=fields["created_at"],
        )

    def to_payload(self) -> dict[str, str]:
        return {
            "run_id": self.run_id,
            "gamever": self.gamever,
            "platforms": self.platforms,
            "modules": self.modules,
            "skill_filter": self.skill_filter or "",
            "agent": self.agent,
            "created_at": self.created_at,
        }


@dataclass(frozen=True)
class QueueEntry:
    entry_id: str
    request: RunRequest
    recovered: bool


class RedisRunQueue:
    def __init__(
        self,
        redis_url: str,
        prefix: str,
        *,
        group: str = "scheduler",
        consumer: str | None = None,
        recovery_idle_ms: int = 30_000,
        stream_maxlen: int = 10_000,
        scheduler_lease_ttl_ms: int = 30_000,
    ):
        self.redis_url = redis_url
        self.keys = RedisKeyBuilder(prefix)
        self.group = _validate_identifier(group, "consumer group")
        self.consumer = consumer or f"{socket.gethostname()}:{os.getpid()}:{uuid.uuid4().hex[:8]}"
        self._scheduler_lease_token = uuid.uuid4().hex
        self.recovery_idle_ms = max(0, recovery_idle_ms)
        self.stream_maxlen = stream_maxlen
        if scheduler_lease_ttl_ms <= 0:
            raise ValueError("Scheduler lease TTL must be positive")
        self.scheduler_lease_ttl_ms = scheduler_lease_ttl_ms
        self.client = Redis.from_url(
            redis_url,
            decode_responses=True,
            socket_connect_timeout=1.0,
            socket_timeout=2.0,
            health_check_interval=15,
        )
        self._submit_script = self.client.register_script(SUBMIT_RUN_LUA)
        self._transition_script = self.client.register_script(SCHEDULER_RUN_TRANSITION_LUA)
        self._renew_lease_script = self.client.register_script(RENEW_SCHEDULER_LEASE_LUA)
        self._release_lease_script = self.client.register_script(RELEASE_SCHEDULER_LEASE_LUA)

    def submit(self, request: RunRequest) -> str:
        payload = request.to_payload()
        result = self._submit_script(
            keys=[
                self.keys.run_queue,
                self.keys.runs,
                self.keys.run_meta(request.run_id),
                self.keys.events(request.run_id),
            ],
            args=[request.run_id, request.created_at, time.time(), json.dumps(payload), self.stream_maxlen],
        )
        if int(result[0]) != 1:
            raise ValueError(f"Run already exists: {request.run_id}")
        return str(result[1])

    def ensure_group(self) -> None:
        try:
            self.client.xgroup_create(self.keys.run_queue, self.group, id="0-0", mkstream=True)
        except ResponseError as exc:
            if "BUSYGROUP" not in str(exc):
                raise

    def next_entry(self, block_ms: int = 1_000) -> QueueEntry | None:
        self.ensure_group()
        if self._pending_count():
            claimed = self.client.xautoclaim(
                self.keys.run_queue,
                self.group,
                self.consumer,
                self.recovery_idle_ms,
                count=1,
            )
            messages = claimed[1] if len(claimed) > 1 else []
            if not messages and block_ms > 0:
                time.sleep(block_ms / 1_000)
            return self._entry(messages, recovered=True)
        response = self.client.xreadgroup(
            self.group,
            self.consumer,
            {self.keys.run_queue: ">"},
            count=1,
            block=block_ms,
        )
        messages = response[0][1] if response else []
        return self._entry(messages, recovered=False)

    def status(self, run_id: str) -> str | None:
        return self.client.hget(self.keys.run_meta(run_id), "status")

    def acquire_scheduler_lease(self) -> bool:
        return bool(
            self.client.set(
                self.keys.scheduler_lease,
                self._scheduler_lease_token,
                nx=True,
                px=self.scheduler_lease_ttl_ms,
            )
        )

    def renew_scheduler_lease(self) -> bool:
        return bool(
            self._renew_lease_script(
                keys=[self.keys.scheduler_lease],
                args=[self._scheduler_lease_token, self.scheduler_lease_ttl_ms],
            )
        )

    def release_scheduler_lease(self) -> None:
        self._release_lease_script(keys=[self.keys.scheduler_lease], args=[self._scheduler_lease_token])

    def has_heartbeat(self, run_id: str) -> bool:
        return bool(self.client.exists(self.keys.heartbeat(run_id)))

    def transition(self, entry: QueueEntry, status: RunStatus, *, exit_code="", error="") -> None:
        result = self._transition_script(
            keys=[
                self.keys.run_meta(entry.request.run_id),
                self.keys.running,
                self.keys.events(entry.request.run_id),
                self.keys.task_status(entry.request.run_id),
                self.keys.task_data(entry.request.run_id),
            ],
            args=[
                entry.request.run_id,
                status.value,
                _utc_now(),
                self.consumer,
                entry.entry_id,
                str(exit_code),
                str(error)[:1_000],
                self.stream_maxlen,
            ],
        )
        if int(result[0]) < 0:
            raise RuntimeError(f"Scheduler transition rejected for {entry.request.run_id}: {result}")

    def ack(self, entry: QueueEntry) -> None:
        self.client.xack(self.keys.run_queue, self.group, entry.entry_id)

    def close(self) -> None:
        self.client.close()

    def _pending_count(self) -> int:
        return int(self.client.xpending(self.keys.run_queue, self.group).get("pending", 0))

    @staticmethod
    def _entry(messages, *, recovered: bool) -> QueueEntry | None:
        if not messages:
            return None
        entry_id, fields = messages[0]
        return QueueEntry(str(entry_id), RunRequest.from_stream(fields), recovered)


class RedisProcessScheduler:
    def __init__(
        self,
        queue: RedisRunQueue,
        *,
        analyzer_script: str | Path = "ida_analyze_bin.py",
        python_executable: str = sys.executable,
        config_path: str | None = None,
        binary_dir: str = "bin",
        workdir: str | Path | None = None,
        popen_factory: Callable = subprocess.Popen,
    ):
        self.queue = queue
        self.analyzer_script = str(Path(analyzer_script).resolve())
        self.python_executable = python_executable
        self.config_path = config_path
        self.binary_dir = binary_dir
        self.workdir = str(Path(workdir or Path(self.analyzer_script).parent).resolve())
        self.popen_factory = popen_factory

    def run_once(self, block_ms: int = 1_000) -> bool:
        if not self.queue.acquire_scheduler_lease():
            if block_ms > 0:
                time.sleep(block_ms / 1_000)
            return False
        stop_renewal = threading.Event()
        renewal_thread = threading.Thread(
            target=self._renew_scheduler_lease,
            args=(stop_renewal,),
            name=f"scheduler-lease-{self.queue.consumer}",
            daemon=True,
        )
        renewal_thread.start()
        try:
            entry = self.queue.next_entry(block_ms)
            if entry is None:
                return False
            self._handle_entry(entry)
            return True
        finally:
            stop_renewal.set()
            renewal_thread.join(timeout=1.0)
            self.queue.release_scheduler_lease()

    def serve_forever(self, poll_ms: int = 1_000) -> None:
        while True:
            self.run_once(poll_ms)

    def build_command(self, request: RunRequest) -> list[str]:
        config_path = resolve_analysis_config(request.gamever, self.config_path)
        command = [
            self.python_executable,
            self.analyzer_script,
            f"-configyaml={config_path}",
            f"-bindir={self.binary_dir}",
            f"-gamever={request.gamever}",
            f"-platform={request.platforms}",
            f"-modules={request.modules}",
            f"-agent={request.agent}",
            "-cache_mode=cold",
        ]
        if request.skill_filter:
            command.append(f"-skill={request.skill_filter}")
        return command

    def build_environment(self, request: RunRequest) -> dict[str, str]:
        return os.environ | {
            "GSVIBE_PROCESS_REPORTER": "redis",
            "GSVIBE_REDIS_URL": self.queue.redis_url,
            "GSVIBE_REDIS_PREFIX": self.queue.keys.prefix,
            "GSVIBE_RUN_ID": request.run_id,
        }

    def _renew_scheduler_lease(self, stop_event: threading.Event) -> None:
        interval = max(0.05, self.queue.scheduler_lease_ttl_ms / 3_000)
        while not stop_event.wait(interval):
            try:
                if not self.queue.renew_scheduler_lease():
                    return
            except Exception:
                continue

    def _handle_entry(self, entry: QueueEntry) -> None:
        run_id = entry.request.run_id
        status = self.queue.status(run_id)
        if status in _TERMINAL_STATUSES:
            self.queue.ack(entry)
            return
        if self.queue.has_heartbeat(run_id):
            return
        if entry.recovered and status in {RunStatus.STARTING.value, RunStatus.RUNNING.value, RunStatus.STALE.value}:
            self.queue.transition(entry, RunStatus.ABORTED, error="Recovered Analyzer heartbeat expired")
            self.queue.ack(entry)
            return
        self.queue.transition(entry, RunStatus.STARTING)
        try:
            process = self.popen_factory(
                self.build_command(entry.request),
                cwd=self.workdir,
                env=self.build_environment(entry.request),
            )
        except Exception as exc:
            self.queue.transition(entry, RunStatus.FAILED, error=f"Analyzer failed to start: {exc}")
            self.queue.ack(entry)
            return
        exit_code = process.wait()
        if self.queue.status(run_id) not in _TERMINAL_STATUSES:
            final_status = RunStatus.SUCCEEDED if exit_code == 0 else RunStatus.FAILED
            self.queue.transition(
                entry, final_status, exit_code=exit_code, error="Analyzer exited without final status"
            )
        self.queue.ack(entry)
