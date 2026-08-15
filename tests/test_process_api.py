import asyncio
import unittest

from fastapi.testclient import TestClient

from process_api import _event_stream, create_app
from process_status_reader_redis import RedisStatusReaderUnavailable


def _run_view(run_id="run-1"):
    return {
        "run_id": run_id,
        "status": "running",
        "effective_status": "running",
        "is_stale": False,
        "heartbeat_alive": True,
        "gamever": "svencoop-10257",
        "agent": "codex",
        "created_at": "2026-07-13T00:00:00+00:00",
        "started_at": None,
        "updated_at": "2026-07-13T00:00:01+00:00",
        "finished_at": None,
        "current_stage_id": None,
        "current_job_id": None,
        "current_skill_id": None,
        "last_event_id": "1-0",
        "error_summary": None,
        "progress": {
            "total": 1,
            "pending": 0,
            "running": 1,
            "succeeded": 0,
            "failed": 0,
            "skipped": 0,
            "aborted": 0,
            "completed": 0,
            "percent": 0.0,
        },
    }


def _task(task_id="stage-0000-engine-windows/vcall/target"):
    return {
        "task_id": task_id,
        "task_type": "vcall_target",
        "name": "target",
        "description": "Export the target vcall",
        "stage_id": "stage-0000-engine",
        "job_id": "stage-0000-engine-windows",
        "status": "running",
        "phase": "vcall_export",
        "reason": None,
        "attempt": None,
        "max_attempts": None,
        "started_at": None,
        "updated_at": "2026-07-13T00:00:01+00:00",
        "finished_at": None,
        "message": None,
        "error": None,
        "payload": {},
        "event_type": "task.status_changed",
        "revision": 1,
    }


def _event(event_id="2-0"):
    return {
        "id": event_id,
        "type": "task.status_changed",
        "run_id": "run-1",
        "task_id": _task()["task_id"],
        "status": "succeeded",
        "phase": "finished",
        "reason": None,
        "occurred_at": "2026-07-13T00:00:02+00:00",
        "revision": 2,
        "data": {"revision": 2},
    }


class FakeReader:
    def __init__(self):
        self.run = _run_view()
        self.graph = {"schema_version": 1, "stages": [], "jobs": [], "nodes": [], "edges": [], "warnings": []}
        self.task = _task()
        self.bounds = {"first": "1-0", "last": "2-0"}
        self.event_batches = []
        self.read_after = []
        self.ready = True

    async def ping(self):
        if not self.ready:
            raise RedisStatusReaderUnavailable("offline")
        return True

    async def close(self):
        return None

    async def list_runs(self, **kwargs):
        return {"items": [self.run], "offset": kwargs["offset"], "next_offset": None, "has_more": False}

    async def get_run(self, run_id):
        return self.run if run_id == self.run["run_id"] else None

    async def get_snapshot(self, run_id):
        if run_id != self.run["run_id"]:
            return None
        return {"run": self.run, "graph": self.graph, "tasks": [self.task], "snapshot_event_id": "1-0"}

    async def get_graph(self, run_id):
        return self.graph if run_id == self.run["run_id"] else None

    async def list_tasks(self, run_id, **kwargs):
        if run_id != self.run["run_id"]:
            return None
        return {"items": [self.task], "offset": kwargs["offset"], "next_offset": None, "has_more": False}

    async def get_task(self, run_id, task_id):
        if run_id == self.run["run_id"] and task_id == self.task["task_id"]:
            return {**self.task, "dependencies": [], "dependents": []}
        return None

    async def get_stream_bounds(self, run_id):
        return self.bounds if run_id == self.run["run_id"] else None

    async def read_events(self, run_id, after, *, count, block_ms=None):
        self.read_after.append(after)
        if self.event_batches:
            result = self.event_batches.pop(0)
            if isinstance(result, BaseException):
                raise result
            return result
        raise RedisStatusReaderUnavailable("stop stream")


class TestProcessApi(unittest.TestCase):
    def setUp(self) -> None:
        self.reader = FakeReader()
        self.app = create_app(self.reader, sse_block_ms=1, sse_batch_size=10)
        self.client = TestClient(self.app)

    def test_rest_routes_and_slash_task_id(self) -> None:
        self.assertEqual(200, self.client.get("/healthz").status_code)
        self.assertEqual(200, self.client.get("/readyz").status_code)
        self.assertEqual(["run-1"], [item["run_id"] for item in self.client.get("/api/v1/runs").json()["items"]])
        self.assertEqual("1-0", self.client.get("/api/v1/runs/run-1/snapshot").json()["snapshot_event_id"])
        response = self.client.get(f"/api/v1/runs/run-1/tasks/{self.reader.task['task_id']}")
        self.assertEqual(200, response.status_code)
        self.assertEqual(self.reader.task["task_id"], response.json()["task_id"])
        self.assertEqual("Export the target vcall", response.json()["description"])

    def test_not_found_graph_not_ready_and_readiness_failure(self) -> None:
        self.assertEqual(404, self.client.get("/api/v1/runs/missing").status_code)
        self.reader.graph = None
        response = self.client.get("/api/v1/runs/run-1/graph")
        self.assertEqual(409, response.status_code)
        self.assertEqual("graph_not_ready", response.json()["detail"]["code"])
        self.reader.ready = False
        self.assertEqual(503, self.client.get("/readyz").status_code)

    def test_sse_uses_query_then_header_cursor_and_formats_event(self) -> None:
        self.reader.event_batches = [[_event()], RedisStatusReaderUnavailable("stop")]
        response = self.client.get(
            "/api/v1/runs/run-1/stream?after=1-0",
            headers={"Last-Event-ID": "0-0"},
        )
        self.assertEqual(200, response.status_code)
        self.assertIn("retry: 3000", response.text)
        self.assertIn("id: 2-0", response.text)
        self.assertIn("event: task.status_changed", response.text)
        self.assertEqual("1-0", self.reader.read_after[0])

    def test_sse_emits_reset_for_expired_cursor(self) -> None:
        self.reader.bounds = {"first": "10-0", "last": "11-0"}
        response = self.client.get("/api/v1/runs/run-1/stream?after=1-0")
        self.assertEqual(200, response.status_code)
        self.assertIn("event: reset", response.text)
        self.assertIn("cursor_expired", response.text)
        self.assertEqual([], self.reader.read_after)

    def test_sse_emits_heartbeat_on_empty_batch(self) -> None:
        self.reader.event_batches = [[], RedisStatusReaderUnavailable("stop")]
        response = self.client.get("/api/v1/runs/run-1/stream?after=1-0")
        self.assertIn(": heartbeat", response.text)

    def test_events_page_expired_cursor_and_invalid_header(self) -> None:
        self.reader.event_batches = [[_event("2-0"), _event("3-0")]]
        response = self.client.get("/api/v1/runs/run-1/events?after=1-0&limit=1")
        self.assertEqual(200, response.status_code)
        self.assertTrue(response.json()["has_more"])
        self.assertEqual("2-0", response.json()["next_after"])

        self.reader.bounds = {"first": "10-0", "last": "11-0"}
        self.assertEqual(409, self.client.get("/api/v1/runs/run-1/events?after=1-0").status_code)
        response = self.client.get("/api/v1/runs/run-1/stream", headers={"Last-Event-ID": "invalid"})
        self.assertEqual(422, response.status_code)

    def test_cors_allowlist_and_openapi_models(self) -> None:
        app = create_app(self.reader, cors_origins=["http://localhost:5173"])
        client = TestClient(app)
        response = client.options(
            "/api/v1/runs",
            headers={"Origin": "http://localhost:5173", "Access-Control-Request-Method": "GET"},
        )
        self.assertEqual("http://localhost:5173", response.headers["access-control-allow-origin"])
        schemas = client.get("/openapi.json").json()["components"]["schemas"]
        self.assertIn("SnapshotResponse", schemas)
        self.assertNotIn("config_path", schemas["RunView"].get("properties", {}))

    def test_private_network_preflight_requires_opt_in_and_allowed_origin(self) -> None:
        headers = {
            "Origin": "https://status.example.com",
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Private-Network": "true",
        }
        disabled = TestClient(
            create_app(
                self.reader,
                cors_origins=["https://status.example.com"],
                allow_private_network=False,
            )
        )
        self.assertNotIn(
            "access-control-allow-private-network",
            disabled.options("/api/v1/runs", headers=headers).headers,
        )

        enabled = TestClient(
            create_app(
                self.reader,
                cors_origins=["https://status.example.com"],
                allow_private_network=True,
            )
        )
        response = enabled.options("/api/v1/runs", headers=headers)
        self.assertEqual("true", response.headers["access-control-allow-private-network"])
        self.assertIn("Access-Control-Request-Private-Network", response.headers["vary"])

        rejected = enabled.options(
            "/api/v1/runs",
            headers={**headers, "Origin": "https://untrusted.example.com"},
        )
        self.assertNotIn("access-control-allow-private-network", rejected.headers)
        with self.assertRaisesRegex(ValueError, "cannot contain"):
            create_app(self.reader, cors_origins=["*"], allow_private_network=True)
        with self.assertRaisesRegex(ValueError, "exact origins"):
            create_app(self.reader, cors_origins=["*"], allow_private_network=False)


class TestSseCancellation(unittest.IsolatedAsyncioTestCase):
    class ConnectedRequest:
        async def is_disconnected(self):
            return False

    async def test_default_cursor_is_anchored_to_a_concrete_stream_id(self) -> None:
        reader = FakeReader()
        reader.event_batches = [[_event("3-0")], RedisStatusReaderUnavailable("stop")]
        stream = _event_stream(self.ConnectedRequest(), reader, "run-1", "$", reader.bounds, 1, 10)

        self.assertEqual("retry: 3000\n\n", await anext(stream))
        self.assertIn("id: 3-0", await anext(stream))
        self.assertEqual("2-0", reader.read_after[0])

    async def test_stream_resets_when_trimming_overtakes_a_live_cursor(self) -> None:
        class TrimmingReader(FakeReader):
            async def read_events(self, run_id, after, *, count, block_ms=None):
                self.read_after.append(after)
                self.bounds = {"first": "10-0", "last": "11-0"}
                return []

        reader = TrimmingReader()
        stream = _event_stream(self.ConnectedRequest(), reader, "run-1", "1-0", reader.bounds, 1, 10)

        self.assertEqual("retry: 3000\n\n", await anext(stream))
        reset = await anext(stream)
        self.assertIn("event: reset", reset)
        self.assertIn("cursor_expired", reset)

    async def test_stream_does_not_swallow_cancellation(self) -> None:
        reader = FakeReader()
        reader.event_batches = [asyncio.CancelledError()]
        stream = _event_stream(self.ConnectedRequest(), reader, "run-1", "1-0", reader.bounds, 1, 10)
        self.assertEqual("retry: 3000\n\n", await anext(stream))
        with self.assertRaises(asyncio.CancelledError):
            await anext(stream)


if __name__ == "__main__":
    unittest.main()
