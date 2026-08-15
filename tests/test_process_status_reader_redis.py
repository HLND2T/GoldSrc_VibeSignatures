import os
import unittest
import uuid

from dotenv import load_dotenv
from redis import Redis
from redis.exceptions import RedisError

from process_reporter import ProcessEvent, ProcessEventType, ProcessPhase, RunStatus, TaskStatus
from process_reporter_redis import RedisProcessReporter
from process_reporter_redis_connection import RedisKeyBuilder
from process_status_reader_redis import RedisProcessStatusReader, RedisStatusDataError


def _sample_plan():
    stage_id = "stage-0000-engine"
    job_id = f"{stage_id}-windows"
    skill_id = f"{job_id}/find-a"
    vcall_id = f"{job_id}/vcall/g_pNetworkMessages"
    return {
        "schema_version": 1,
        "stages": [
            {
                "id": stage_id,
                "stage_index": 0,
                "module_name": "engine",
                "description": "Engine analysis stage",
            }
        ],
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
                "id": skill_id,
                "job_id": job_id,
                "stage_id": stage_id,
                "name": "find-a",
                "node_type": "skill",
                "order": 0,
                "layer": 0,
                "description": "Locate find-a",
                "data": {},
            },
            {
                "id": vcall_id,
                "job_id": job_id,
                "stage_id": stage_id,
                "name": "g_pNetworkMessages",
                "node_type": "vcall_target",
                "order": 1,
                "layer": 1,
                "data": {},
            },
        ],
        "edges": [{"source": skill_id, "target": vcall_id, "edge_type": "artifact", "artifact": "a.yaml"}],
        "warnings": [],
    }


class TestRedisProcessStatusReader(unittest.IsolatedAsyncioTestCase):
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

    async def asyncSetUp(self) -> None:
        self.prefix = f"gsvibe:test:reader:{uuid.uuid4().hex}"
        self.keys = RedisKeyBuilder(self.prefix)
        self.reader = RedisProcessStatusReader(self.redis_url, self.prefix)
        self.reporters = []

    async def asyncTearDown(self) -> None:
        for reporter in self.reporters:
            reporter.close()
        await self.reader.close()
        keys = list(self.redis.scan_iter(f"{self.prefix}:*"))
        if keys:
            self.redis.delete(*keys)

    def _seed_run(self, run_id: str, score: float, status: str, gamever: str = "svencoop-10257") -> None:
        self.redis.zadd(self.keys.runs, {run_id: score})
        self.redis.hset(
            self.keys.run_meta(run_id),
            mapping={
                "status": status,
                "gamever": gamever,
                "agent": "codex",
                "created_at": f"2026-07-13T00:00:0{int(score)}+00:00",
                "updated_at": "2026-07-13T00:00:10+00:00",
                "total": "4",
                "pending": "1",
                "running": "1",
                "succeeded": "1",
                "failed": "1",
                "skipped": "0",
                "aborted": "0",
                "config_path": "secret/path/config.yaml",
                "scheduler_consumer": "host:pid",
            },
        )

    def _create_reporter(self, plan, run_id="run-detail"):
        reporter = RedisProcessReporter(
            self.redis_url,
            self.prefix,
            run_metadata={"gamever": "svencoop-10257", "agent": "codex"},
            heartbeat_interval=60,
        )
        self.reporters.append(reporter)
        reporter.initialize_run(plan, run_id=run_id)
        return reporter

    async def test_lists_runs_in_reverse_order_with_filters_and_safe_fields(self) -> None:
        self._seed_run("run-1", 1, "succeeded", "svencoop-10257")
        self._seed_run("run-2", 2, "failed", "cstrike-10210")
        self._seed_run("run-3", 3, "succeeded", "svencoop-10257")

        page = await self.reader.list_runs(
            offset=0,
            limit=1,
            status="succeeded",
            gamever="svencoop-10257",
        )

        self.assertEqual(["run-3"], [item["run_id"] for item in page["items"]])
        self.assertTrue(page["has_more"])
        self.assertEqual(
            "run-1", (await self.reader.list_runs(offset=page["next_offset"], limit=1))["items"][0]["run_id"]
        )
        run = page["items"][0]
        self.assertEqual(50.0, run["progress"]["percent"])
        self.assertNotIn("config_path", run)
        self.assertNotIn("scheduler_consumer", run)

    async def test_derives_stale_only_for_running_runs_without_heartbeat(self) -> None:
        self._seed_run("running", 1, "running")
        self._seed_run("starting", 2, "starting")
        self._seed_run("finished", 3, "succeeded")

        running = await self.reader.get_run("running")
        self.assertEqual("stale", running["effective_status"])
        self.assertTrue(running["is_stale"])
        self.assertEqual("starting", (await self.reader.get_run("starting"))["effective_status"])
        self.assertEqual("succeeded", (await self.reader.get_run("finished"))["effective_status"])

        self.redis.set(self.keys.heartbeat("running"), "worker", ex=30)
        self.assertEqual("running", (await self.reader.get_run("running"))["effective_status"])

    async def test_reads_snapshot_order_task_detail_and_resume_events(self) -> None:
        plan = _sample_plan()
        reporter = self._create_reporter(plan)
        job_id = plan["jobs"][0]["id"]
        skill_id, vcall_id = [node["id"] for node in plan["nodes"]]
        reporter.emit(ProcessEvent("run-detail", ProcessEventType.RUN_STATUS_CHANGED, status=RunStatus.RUNNING))
        reporter.emit(
            ProcessEvent(
                "run-detail",
                ProcessEventType.TASK_STATUS_CHANGED,
                skill_id,
                TaskStatus.RUNNING,
                ProcessPhase.PREPROCESSING,
            )
        )

        snapshot = await self.reader.get_snapshot("run-detail")
        self.assertEqual([job_id, skill_id, vcall_id], [task["task_id"] for task in snapshot["tasks"]])
        self.assertEqual("Engine analysis stage", snapshot["tasks"][0]["description"])
        self.assertEqual("Locate find-a", snapshot["tasks"][1]["description"])
        self.assertIsNone(snapshot["tasks"][2]["description"])
        self.assertEqual(snapshot["run"]["last_event_id"], snapshot["snapshot_event_id"])

        reporter.emit(
            ProcessEvent(
                "run-detail",
                ProcessEventType.TASK_STATUS_CHANGED,
                skill_id,
                TaskStatus.SUCCEEDED,
                ProcessPhase.FINISHED,
            )
        )
        events = await self.reader.read_events("run-detail", snapshot["snapshot_event_id"], count=10)
        self.assertEqual(1, len(events))
        self.assertEqual(skill_id, events[0]["task_id"])
        detail = await self.reader.get_task("run-detail", vcall_id)
        self.assertEqual([skill_id], detail["dependencies"])
        self.assertEqual([], detail["dependents"])
        page = await self.reader.list_tasks("run-detail", task_type="vcall_target", offset=0, limit=10)
        self.assertEqual([vcall_id], [task["task_id"] for task in page["items"]])

    async def test_legacy_graph_without_descriptions_returns_null_task_descriptions(self) -> None:
        plan = _sample_plan()
        plan["stages"][0].pop("description")
        plan["nodes"][0].pop("description")
        self._create_reporter(plan, run_id="legacy-description")

        snapshot = await self.reader.get_snapshot("legacy-description")

        self.assertTrue(all(task["description"] is None for task in snapshot["tasks"]))

    async def test_queued_snapshot_and_stream_bounds(self) -> None:
        self._seed_run("queued", 1, "queued")
        first_id = self.redis.xadd(self.keys.events("queued"), {"type": "run.queued", "data": "{}"})
        self.redis.hset(self.keys.run_meta("queued"), "last_event_id", first_id)

        snapshot = await self.reader.get_snapshot("queued")
        self.assertIsNone(snapshot["graph"])
        self.assertEqual([], snapshot["tasks"])
        self.assertEqual({"first": first_id, "last": first_id}, await self.reader.get_stream_bounds("queued"))

    async def test_retained_event_bounds_and_corrupt_graph(self) -> None:
        self._seed_run("trimmed", 1, "succeeded")
        event_ids = [
            self.redis.xadd(self.keys.events("trimmed"), {"type": "run.status_changed", "data": "{}"}) for _ in range(4)
        ]
        self.redis.xtrim(self.keys.events("trimmed"), maxlen=2, approximate=False)

        bounds = await self.reader.get_stream_bounds("trimmed")
        self.assertEqual(event_ids[-2], bounds["first"])
        events = await self.reader.read_events("trimmed", event_ids[-2], count=10)
        self.assertEqual([event_ids[-1]], [event["id"] for event in events])

        self.redis.set(self.keys.graph("trimmed"), "not-json")
        with self.assertRaises(RedisStatusDataError):
            await self.reader.get_graph("trimmed")


if __name__ == "__main__":
    unittest.main()
