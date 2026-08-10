import json
import os
import time
import unittest
import uuid
from unittest.mock import patch

from dotenv import load_dotenv
from redis import Redis
from redis.exceptions import RedisError

from process_reporter import (
    ProcessEvent,
    ProcessEventType,
    ProcessPhase,
    ProcessReason,
    RunStatus,
    TaskStatus,
)
from process_reporter_redis import RedisKeyBuilder, RedisProcessReporter


def _sample_plan():
    stage_id = "stage-0000-engine"
    job_id = f"{stage_id}-windows"
    return {
        "schema_version": 1,
        "stages": [{"id": stage_id, "stage_index": 0, "module_name": "engine"}],
        "jobs": [
            {
                "id": job_id,
                "stage_id": stage_id,
                "stage_index": 0,
                "module_name": "engine",
                "platform": "windows",
                "binary_path": "bin/1/engine/engine2.dll",
            }
        ],
        "nodes": [
            {
                "id": f"{job_id}/find-a",
                "job_id": job_id,
                "stage_id": stage_id,
                "name": "find-a",
                "node_type": "skill",
                "order": 0,
                "layer": 0,
                "data": {},
            },
            {
                "id": f"{job_id}/find-b",
                "job_id": job_id,
                "stage_id": stage_id,
                "name": "find-b",
                "node_type": "skill",
                "order": 1,
                "layer": 1,
                "data": {},
            },
        ],
        "edges": [],
        "warnings": [],
    }


class TestRedisKeyBuilder(unittest.TestCase):
    def test_normalizes_prefix_and_builds_run_keys(self) -> None:
        keys = RedisKeyBuilder(" :gsvibe:test: ")

        self.assertEqual("gsvibe:test:runs", keys.runs)
        self.assertEqual("gsvibe:test:run-queue", keys.run_queue)
        self.assertEqual("gsvibe:test:run:run-1:events", keys.events("run-1"))
        with self.assertRaises(ValueError):
            RedisKeyBuilder("::")


class TestRedisProcessReporterIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        load_dotenv()
        cls.redis_url = os.environ.get("GSVIBE_REDIS_URL", "redis://127.0.0.1:6379/0")
        cls.redis = Redis.from_url(cls.redis_url, decode_responses=True)
        try:
            cls.redis.ping()
        except RedisError as exc:
            raise unittest.SkipTest(f"Redis integration server is unavailable: {exc}") from exc

    @classmethod
    def tearDownClass(cls) -> None:
        cls.redis.close()

    def _create_reporter(self, **overrides):
        prefix = f"gsvibe:test:{uuid.uuid4().hex}"
        self.addCleanup(self._delete_prefix, prefix)
        settings = {
            "redis_url": self.redis_url,
            "prefix": prefix,
            "heartbeat_ttl": 3,
            "heartbeat_interval": 0.2,
            "worker_id": "integration-worker",
        }
        settings.update(overrides)
        reporter = RedisProcessReporter(**settings)
        self.addCleanup(reporter.close)
        return reporter, reporter.keys

    def _delete_prefix(self, prefix: str) -> None:
        keys = list(self.redis.scan_iter(f"{prefix}:*"))
        if keys:
            self.redis.delete(*keys)

    def _emit_successful_lifecycle(self, reporter, run_id, job_id, task_a, task_b) -> None:
        events = [
            ProcessEvent(run_id, ProcessEventType.RUN_STATUS_CHANGED, status=RunStatus.RUNNING),
            ProcessEvent(
                run_id,
                ProcessEventType.TASK_STATUS_CHANGED,
                job_id,
                TaskStatus.RUNNING,
                ProcessPhase.WAITING_FOR_MCP,
            ),
            ProcessEvent(
                run_id,
                ProcessEventType.TASK_STATUS_CHANGED,
                task_a,
                TaskStatus.RUNNING,
                ProcessPhase.PREPROCESSING,
            ),
            ProcessEvent(
                run_id,
                ProcessEventType.SKILL_PROGRESS,
                task_a,
                TaskStatus.RUNNING,
                ProcessPhase.AGENT_FALLBACK,
                payload={"attempt": 2, "max_attempts": 3},
            ),
            ProcessEvent(
                run_id,
                ProcessEventType.TASK_STATUS_CHANGED,
                task_a,
                TaskStatus.SUCCEEDED,
                ProcessPhase.FINISHED,
            ),
            ProcessEvent(
                run_id,
                ProcessEventType.TASK_STATUS_CHANGED,
                task_b,
                TaskStatus.SKIPPED,
                ProcessPhase.FINISHED,
                ProcessReason.EXISTING_OUTPUTS,
            ),
            ProcessEvent(run_id, ProcessEventType.RUN_STATUS_CHANGED, status=RunStatus.SUCCEEDED),
        ]
        for event in events:
            reporter.emit(event)

    def test_initialize_writes_graph_pending_snapshots_and_safe_metadata(self) -> None:
        reporter, keys = self._create_reporter(
            run_metadata={
                "gamever": "svencoop-10257",
                "agent": "codex",
                "llm_apikey": "must-not-be-written",
            }
        )
        plan = _sample_plan()

        run_id = reporter.initialize_run(plan, run_id="run-init")

        meta = self.redis.hgetall(keys.run_meta(run_id))
        statuses = self.redis.hgetall(keys.task_status(run_id))
        self.assertEqual("starting", meta["status"])
        self.assertEqual("2", meta["total"])
        self.assertEqual("2", meta["pending"])
        self.assertEqual("svencoop-10257", meta["gamever"])
        self.assertNotIn("llm_apikey", meta)
        self.assertEqual(plan, json.loads(self.redis.get(keys.graph(run_id))))
        self.assertEqual(3, len(statuses))
        self.assertEqual({"pending"}, set(statuses.values()))
        self.assertIsNotNone(self.redis.zscore(keys.runs, run_id))
        events = self.redis.xrange(keys.events(run_id))
        self.assertEqual("run.initialized", events[0][1]["type"])

    def test_transitions_update_snapshot_summary_stream_and_finalize_atomically(self) -> None:
        reporter, keys = self._create_reporter()
        plan = _sample_plan()
        run_id = reporter.initialize_run(plan, run_id="run-transition")
        job_id = plan["jobs"][0]["id"]
        task_a, task_b = [node["id"] for node in plan["nodes"]]

        self._emit_successful_lifecycle(reporter, run_id, job_id, task_a, task_b)
        summary = {"total": 2, "pending": 0, "running": 0, "succeeded": 1, "failed": 0, "skipped": 1, "aborted": 0}
        reporter.finalize_run(run_id, RunStatus.SUCCEEDED, summary)

        meta = self.redis.hgetall(keys.run_meta(run_id))
        task_data = json.loads(self.redis.hget(keys.task_data(run_id), task_a))
        events = self.redis.xrange(keys.events(run_id))
        self.assertEqual("succeeded", meta["status"])
        self.assertEqual("1", meta["succeeded"])
        self.assertEqual("1", meta["skipped"])
        self.assertEqual(task_b, meta["current_skill_id"])
        self.assertEqual("3", str(task_data["revision"]))
        self.assertEqual(2, task_data["attempt"])
        self.assertEqual(events[-1][0], meta["last_event_id"])
        self.assertFalse(self.redis.sismember(keys.running, run_id))

    def test_stale_resync_is_idempotent_and_terminal_regression_is_rejected(self) -> None:
        warnings = []
        reporter, keys = self._create_reporter(warning_callback=warnings.append)
        plan = _sample_plan()
        run_id = reporter.initialize_run(plan, run_id="run-idempotent")
        task_id = plan["nodes"][0]["id"]
        reporter.emit(
            ProcessEvent(
                run_id, ProcessEventType.TASK_STATUS_CHANGED, task_id, TaskStatus.RUNNING, ProcessPhase.PREFLIGHT
            )
        )
        reporter.emit(
            ProcessEvent(
                run_id, ProcessEventType.TASK_STATUS_CHANGED, task_id, TaskStatus.SUCCEEDED, ProcessPhase.FINISHED
            )
        )
        event_count = self.redis.xlen(keys.events(run_id))
        reporter._dirty = True
        reporter.flush()
        self.assertEqual(event_count, self.redis.xlen(keys.events(run_id)))

        reporter.emit(
            ProcessEvent(
                run_id, ProcessEventType.TASK_STATUS_CHANGED, task_id, TaskStatus.RUNNING, ProcessPhase.PREFLIGHT
            )
        )
        data = json.loads(self.redis.hget(keys.task_data(run_id), task_id))
        self.assertEqual("succeeded", data["status"])
        self.assertEqual(2, data["revision"])
        self.assertTrue(any("invalid transition" in warning for warning in warnings))

    def test_finalize_does_not_overwrite_a_different_terminal_status(self) -> None:
        reporter, keys = self._create_reporter()
        run_id = reporter.initialize_run(_sample_plan(), run_id="run-terminal-race")
        self.redis.hset(keys.run_meta(run_id), "status", RunStatus.ABORTED.value)

        reporter.finalize_run(
            run_id,
            RunStatus.SUCCEEDED,
            {"total": 2, "pending": 0, "running": 0, "succeeded": 2, "failed": 0, "skipped": 0, "aborted": 0},
        )

        meta = self.redis.hgetall(keys.run_meta(run_id))
        self.assertEqual("aborted", meta["status"])
        self.assertEqual("2", meta["pending"])

    def test_transient_failure_resyncs_latest_snapshot_and_heartbeat_expires(self) -> None:
        warnings = []
        reporter, keys = self._create_reporter(
            warning_callback=warnings.append,
            heartbeat_ttl=1,
            heartbeat_interval=0.1,
        )
        plan = _sample_plan()
        run_id = reporter.initialize_run(plan, run_id="run-resync")
        task_id = plan["nodes"][0]["id"]
        with patch.object(reporter._connection, "task_transition", side_effect=RedisError("offline")):
            reporter.emit(
                ProcessEvent(
                    run_id, ProcessEventType.TASK_STATUS_CHANGED, task_id, TaskStatus.RUNNING, ProcessPhase.PREFLIGHT
                )
            )
            reporter.emit(
                ProcessEvent(
                    run_id, ProcessEventType.TASK_STATUS_CHANGED, task_id, TaskStatus.FAILED, ProcessPhase.FINISHED
                )
            )

        self.assertEqual("pending", self.redis.hget(keys.task_status(run_id), task_id))
        reporter.flush()
        data = json.loads(self.redis.hget(keys.task_data(run_id), task_id))
        self.assertEqual("failed", data["status"])
        self.assertEqual(2, data["revision"])
        self.assertTrue(any("queued for resync" in warning for warning in warnings))
        self.assertTrue(any("resynchronized" in warning for warning in warnings))

        time.sleep(0.25)
        self.assertGreater(self.redis.ttl(keys.heartbeat(run_id)), 0)
        reporter.close()
        time.sleep(1.1)
        self.assertIsNone(self.redis.get(keys.heartbeat(run_id)))

    def test_stream_trimming_keeps_latest_snapshot(self) -> None:
        reporter, keys = self._create_reporter(stream_maxlen=5)
        plan = _sample_plan()
        run_id = reporter.initialize_run(plan, run_id="run-trim")
        task_id = plan["nodes"][0]["id"]
        reporter.emit(
            ProcessEvent(
                run_id, ProcessEventType.TASK_STATUS_CHANGED, task_id, TaskStatus.RUNNING, ProcessPhase.PREFLIGHT
            )
        )
        for attempt in range(150):
            reporter.emit(
                ProcessEvent(
                    run_id,
                    ProcessEventType.SKILL_PROGRESS,
                    task_id,
                    TaskStatus.RUNNING,
                    ProcessPhase.AGENT_FALLBACK,
                    payload={"attempt": attempt + 1},
                )
            )

        data = json.loads(self.redis.hget(keys.task_data(run_id), task_id))
        self.assertEqual(151, data["revision"])
        self.assertLess(self.redis.xlen(keys.events(run_id)), 152)


if __name__ == "__main__":
    unittest.main()
