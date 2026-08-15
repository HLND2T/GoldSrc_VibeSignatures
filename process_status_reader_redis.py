"""Asynchronous, read-only Redis adapter for process status data."""

from typing import Any

from redis.asyncio import Redis
from redis.exceptions import RedisError, ResponseError

from process_reporter_redis_connection import RedisKeyBuilder
from process_status_reader_redis_views import RedisStatusDataError as RedisStatusDataError
from process_status_reader_redis_views import event_view, json_object, run_view, task_views


class RedisStatusReaderError(RuntimeError):
    """Base class for safe read-model failures."""


class RedisStatusReaderUnavailable(RedisStatusReaderError):
    """Raised when Redis cannot serve a status query."""


class RedisProcessStatusReader:
    """Query normalized run snapshots and retained event streams."""

    def __init__(self, redis_url: str, prefix: str):
        self.keys = RedisKeyBuilder(prefix)
        self._client = Redis.from_url(
            redis_url,
            decode_responses=True,
            socket_connect_timeout=1.0,
            socket_timeout=None,
            health_check_interval=15,
        )

    async def ping(self) -> bool:
        return bool(await self._call("ping"))

    async def close(self) -> None:
        await self._client.aclose()

    async def list_runs(self, *, offset=0, limit=50, status=None, gamever=None) -> dict[str, Any]:
        scan_offset = offset
        matches: list[tuple[int, dict[str, Any]]] = []
        while len(matches) <= limit:
            rows = await self._call("zrevrange", self.keys.runs, scan_offset, scan_offset + 99, withscores=True)
            if not rows:
                break
            views = await self._load_run_batch([str(row[0]) for row in rows])
            for index, view in enumerate(views):
                raw_index = scan_offset + index
                if self._run_matches(view, status, gamever):
                    matches.append((raw_index, view))
                    if len(matches) > limit:
                        break
            if len(matches) > limit or len(rows) < 100:
                break
            scan_offset += len(rows)
        has_more = len(matches) > limit
        items = [view for _, view in matches[:limit]]
        next_offset = matches[limit][0] if has_more else None
        return {"items": items, "offset": offset, "next_offset": next_offset, "has_more": has_more}

    async def get_run(self, run_id: str) -> dict[str, Any] | None:
        pipeline = self._client.pipeline(transaction=False)
        pipeline.hgetall(self.keys.run_meta(run_id))
        pipeline.exists(self.keys.heartbeat(run_id))
        meta, heartbeat = await self._execute(pipeline)
        return run_view(run_id, meta, bool(heartbeat)) if meta else None

    async def get_graph(self, run_id: str) -> dict[str, Any] | None:
        return json_object(await self._call("get", self.keys.graph(run_id)), "execution plan")

    async def list_tasks(
        self, run_id: str, *, status=None, task_type=None, stage_id=None, job_id=None, offset=0, limit=200
    ):
        if not await self._call("exists", self.keys.run_meta(run_id)):
            return None
        graph = await self.get_graph(run_id)
        task_data = await self._call("hgetall", self.keys.task_data(run_id))
        tasks = task_views(graph, task_data)
        tasks = [task for task in tasks if self._task_matches(task, status, task_type, stage_id, job_id)]
        page = tasks[offset : offset + limit + 1]
        has_more = len(page) > limit
        return {
            "items": page[:limit],
            "offset": offset,
            "next_offset": offset + limit if has_more else None,
            "has_more": has_more,
        }

    async def get_task(self, run_id: str, task_id: str) -> dict[str, Any] | None:
        raw = await self._call("hget", self.keys.task_data(run_id), task_id)
        if raw is None:
            return None
        graph = await self.get_graph(run_id)
        task = task_views(graph, {task_id: raw})[0]
        edges = (graph or {}).get("edges", [])
        task["dependencies"] = [edge["source"] for edge in edges if edge.get("target") == task_id]
        task["dependents"] = [edge["target"] for edge in edges if edge.get("source") == task_id]
        return task

    async def get_snapshot(self, run_id: str) -> dict[str, Any] | None:
        meta_key = self.keys.run_meta(run_id)
        if not await self._call("exists", meta_key):
            return None
        snapshot_event_id = await self._call("hget", meta_key, "last_event_id") or "0-0"
        pipeline = self._client.pipeline(transaction=False)
        pipeline.hgetall(meta_key)
        pipeline.get(self.keys.graph(run_id))
        pipeline.hgetall(self.keys.task_data(run_id))
        pipeline.exists(self.keys.heartbeat(run_id))
        meta, raw_graph, task_data, heartbeat = await self._execute(pipeline)
        graph = json_object(raw_graph, "execution plan")
        return {
            "run": run_view(run_id, meta, bool(heartbeat)),
            "graph": graph,
            "tasks": task_views(graph, task_data),
            "snapshot_event_id": snapshot_event_id,
        }

    async def read_events(self, run_id: str, after: str, *, count: int, block_ms: int | None = None):
        key = self.keys.events(run_id)
        if block_ms is None:
            rows = await self._call("xrange", key, min=f"({after}", max="+", count=count)
        else:
            streams = await self._call("xread", {key: after}, count=count, block=block_ms)
            rows = streams[0][1] if streams else []
        return [event_view(run_id, event_id, fields) for event_id, fields in rows]

    async def get_stream_bounds(self, run_id: str) -> dict[str, str] | None:
        try:
            info = await self._call("xinfo_stream", self.keys.events(run_id))
        except RedisStatusReaderUnavailable as exc:
            if isinstance(exc.__cause__, ResponseError) and "no such key" in str(exc.__cause__).lower():
                return None
            raise
        first = info.get("first-entry")
        last = info.get("last-entry")
        if not first or not last:
            return None
        return {"first": str(first[0]), "last": str(last[0])}

    async def _load_run_batch(self, run_ids: list[str]) -> list[dict[str, Any]]:
        pipeline = self._client.pipeline(transaction=False)
        for run_id in run_ids:
            pipeline.hgetall(self.keys.run_meta(run_id))
            pipeline.exists(self.keys.heartbeat(run_id))
        results = await self._execute(pipeline)
        return [
            run_view(run_id, results[index * 2], bool(results[index * 2 + 1])) for index, run_id in enumerate(run_ids)
        ]

    @staticmethod
    def _run_matches(view, status, gamever) -> bool:
        return (status is None or view["effective_status"] == status) and (
            gamever is None or view["gamever"] == gamever
        )

    @staticmethod
    def _task_matches(task, status, task_type, stage_id, job_id) -> bool:
        filters = (("status", status), ("task_type", task_type), ("stage_id", stage_id), ("job_id", job_id))
        return all(value is None or task[key] == value for key, value in filters)

    async def _call(self, method: str, *args, **kwargs):
        try:
            return await getattr(self._client, method)(*args, **kwargs)
        except RedisError as exc:
            raise RedisStatusReaderUnavailable("Redis status service is unavailable") from exc

    async def _execute(self, pipeline):
        try:
            return await pipeline.execute()
        except RedisError as exc:
            raise RedisStatusReaderUnavailable("Redis status service is unavailable") from exc
