"""Read-only FastAPI service for Redis-backed process status and SSE."""

import json
import logging
import os
import re
from contextlib import asynccontextmanager
from typing import Annotated, Any

import uvicorn
from dotenv import load_dotenv
from fastapi import APIRouter, FastAPI, Header, HTTPException, Path, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from starlette.datastructures import Headers, MutableHeaders

from process_api_schemas import (
    EventPageResponse,
    ExecutionPlanView,
    HealthResponse,
    RunPageResponse,
    RunView,
    SnapshotResponse,
    TaskDetail,
    TaskPageResponse,
)
from process_reporter import RunStatus, TaskStatus
from process_reporter_factory import DEFAULT_REDIS_PREFIX, DEFAULT_REDIS_URL
from process_status_reader_redis import (
    RedisProcessStatusReader,
    RedisStatusDataError,
    RedisStatusReaderUnavailable,
)

load_dotenv()
LOGGER = logging.getLogger(__name__)
RUN_ID_PATTERN = r"^[A-Za-z0-9_.:-]{1,160}$"
STREAM_ID_PATTERN = re.compile(r"^\d+-\d+$")
RunId = Annotated[str, Path(pattern=RUN_ID_PATTERN)]
router = APIRouter(prefix="/api/v1")


class PrivateNetworkAccessMiddleware:
    """Allow opted-in browser private-network preflights for trusted origins."""

    def __init__(self, app, allowed_origins):
        self.app = app
        self.allowed_origins = frozenset(origin for origin in allowed_origins if origin != "*")

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or not self._allows(scope):
            await self.app(scope, receive, send)
            return

        async def send_with_private_network(message):
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                headers["Access-Control-Allow-Private-Network"] = "true"
                _append_vary(headers, "Access-Control-Request-Private-Network")
            await send(message)

        await self.app(scope, receive, send_with_private_network)

    def _allows(self, scope) -> bool:
        headers = Headers(scope=scope)
        return (
            scope.get("method") == "OPTIONS"
            and headers.get("origin") in self.allowed_origins
            and headers.get("access-control-request-private-network", "").lower() == "true"
        )


def _append_vary(headers: MutableHeaders, value: str) -> None:
    existing = [item.strip() for item in headers.get("Vary", "").split(",") if item.strip()]
    if value.lower() not in {item.lower() for item in existing}:
        existing.append(value)
    headers["Vary"] = ", ".join(existing)


def _reader(request: Request):
    return request.app.state.status_reader


def _error(status_code: int, code: str, message: str) -> HTTPException:
    return HTTPException(status_code=status_code, detail={"code": code, "message": message})


def _stream_tuple(stream_id: str) -> tuple[int, int]:
    first, second = stream_id.split("-", 1)
    return int(first), int(second)


def _cursor_expired(after: str, bounds: dict[str, str] | None) -> bool:
    return bool(bounds and after not in {"0-0", "$"} and _stream_tuple(after) < _stream_tuple(bounds["first"]))


def _validate_header_cursor(value: str | None) -> str | None:
    if value is not None and not STREAM_ID_PATTERN.fullmatch(value):
        raise _error(422, "invalid_event_cursor", "Last-Event-ID must be a Redis Stream ID")
    return value


def _sse_event(event: dict[str, Any]) -> str:
    data = json.dumps(event, ensure_ascii=False, separators=(",", ":"), default=str)
    return f"id: {event['id']}\nevent: {event['type']}\ndata: {data}\n\n"


def _sse_reset(run_id: str, after: str, first_event_id: str) -> str:
    data = {
        "code": "cursor_expired",
        "after": after,
        "first_event_id": first_event_id,
        "snapshot_url": f"/api/v1/runs/{run_id}/snapshot",
    }
    return f"event: reset\ndata: {json.dumps(data, separators=(',', ':'))}\n\n"


async def _event_stream(request, reader, run_id, cursor, bounds, block_ms, batch_size):
    yield "retry: 3000\n\n"
    if cursor == "$":
        cursor = bounds["last"] if bounds else "0-0"
    if _cursor_expired(cursor, bounds):
        yield _sse_reset(run_id, cursor, bounds["first"])
        return
    while not await request.is_disconnected():
        try:
            bounds = await reader.get_stream_bounds(run_id)
            if _cursor_expired(cursor, bounds):
                yield _sse_reset(run_id, cursor, bounds["first"])
                return
            events = await reader.read_events(run_id, cursor, count=batch_size, block_ms=block_ms)
            latest_bounds = await reader.get_stream_bounds(run_id)
        except RedisStatusReaderUnavailable:
            LOGGER.warning("Redis status stream became unavailable for run %s", run_id)
            return
        if _cursor_expired(cursor, latest_bounds):
            yield _sse_reset(run_id, cursor, latest_bounds["first"])
            return
        if not events:
            yield ": heartbeat\n\n"
            continue
        for event in events:
            cursor = event["id"]
            yield _sse_event(event)


@router.get("/runs", response_model=RunPageResponse)
async def list_runs(
    request: Request,
    offset: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    status: RunStatus | None = None,
    gamever: str | None = None,
):
    status_value = status.value if status else None
    return await _reader(request).list_runs(offset=offset, limit=limit, status=status_value, gamever=gamever)


@router.get("/runs/{run_id}", response_model=RunView)
async def get_run(request: Request, run_id: RunId):
    run = await _reader(request).get_run(run_id)
    if run is None:
        raise _error(404, "run_not_found", "Run was not found")
    return run


@router.get("/runs/{run_id}/snapshot", response_model=SnapshotResponse)
async def get_snapshot(request: Request, run_id: RunId):
    snapshot = await _reader(request).get_snapshot(run_id)
    if snapshot is None:
        raise _error(404, "run_not_found", "Run was not found")
    return snapshot


@router.get("/runs/{run_id}/graph", response_model=ExecutionPlanView)
async def get_graph(request: Request, run_id: RunId):
    reader = _reader(request)
    if await reader.get_run(run_id) is None:
        raise _error(404, "run_not_found", "Run was not found")
    graph = await reader.get_graph(run_id)
    if graph is None:
        raise _error(409, "graph_not_ready", "Execution graph has not been initialized")
    return graph


@router.get("/runs/{run_id}/tasks", response_model=TaskPageResponse)
async def list_tasks(
    request: Request,
    run_id: RunId,
    status: TaskStatus | None = None,
    task_type: str | None = None,
    stage_id: str | None = None,
    job_id: str | None = None,
    offset: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=1000)] = 200,
):
    page = await _reader(request).list_tasks(
        run_id,
        status=status.value if status else None,
        task_type=task_type,
        stage_id=stage_id,
        job_id=job_id,
        offset=offset,
        limit=limit,
    )
    if page is None:
        raise _error(404, "run_not_found", "Run was not found")
    return page


@router.get("/runs/{run_id}/tasks/{task_id:path}", response_model=TaskDetail)
async def get_task(request: Request, run_id: RunId, task_id: str):
    task = await _reader(request).get_task(run_id, task_id)
    if task is None:
        if await _reader(request).get_run(run_id) is None:
            raise _error(404, "run_not_found", "Run was not found")
        raise _error(404, "task_not_found", "Task was not found")
    return task


@router.get("/runs/{run_id}/events", response_model=EventPageResponse)
async def get_events(
    request: Request,
    run_id: RunId,
    after: Annotated[str, Query(pattern=r"^\d+-\d+$")] = "0-0",
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
):
    reader = _reader(request)
    if await reader.get_run(run_id) is None:
        raise _error(404, "run_not_found", "Run was not found")
    bounds = await reader.get_stream_bounds(run_id)
    if _cursor_expired(after, bounds):
        raise _error(409, "cursor_expired", "Event cursor is older than the retained stream")
    events = await reader.read_events(run_id, after, count=limit + 1)
    has_more = len(events) > limit
    items = events[:limit]
    return {"items": items, "next_after": items[-1]["id"] if items else after, "has_more": has_more}


@router.get("/runs/{run_id}/stream")
async def stream_events(
    request: Request,
    run_id: RunId,
    after: Annotated[str | None, Query(pattern=r"^\d+-\d+$")] = None,
    last_event_id: str | None = Header(default=None, alias="Last-Event-ID"),
):
    reader = _reader(request)
    if await reader.get_run(run_id) is None:
        raise _error(404, "run_not_found", "Run was not found")
    cursor = after or _validate_header_cursor(last_event_id) or "$"
    bounds = await reader.get_stream_bounds(run_id)
    body = _event_stream(
        request, reader, run_id, cursor, bounds, request.app.state.sse_block_ms, request.app.state.sse_batch_size
    )
    headers = {"Cache-Control": "no-cache", "Connection": "keep-alive", "X-Accel-Buffering": "no"}
    return StreamingResponse(body, media_type="text/event-stream", headers=headers)


async def _unavailable_handler(_request: Request, _exc: RedisStatusReaderUnavailable):
    return JSONResponse(
        status_code=503, content={"detail": {"code": "redis_unavailable", "message": "Status service is unavailable"}}
    )


async def _data_error_handler(_request: Request, _exc: RedisStatusDataError):
    return JSONResponse(
        status_code=500, content={"detail": {"code": "status_data_invalid", "message": "Stored status data is invalid"}}
    )


def _origins_from_environment() -> list[str]:
    return [item.strip() for item in os.environ.get("GSVIBE_API_CORS_ORIGINS", "").split(",") if item.strip()]


def _positive_environment(name: str, default: int) -> int:
    value = int(os.environ.get(name, default))
    if value <= 0:
        raise ValueError(f"{name} must be positive")
    return value


def _boolean_environment(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    normalized = raw.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"{name} must be a boolean")


def create_app(
    reader=None,
    *,
    cors_origins=None,
    sse_block_ms=None,
    sse_batch_size=None,
    allow_private_network=None,
) -> FastAPI:
    owns_reader = reader is None
    status_reader = reader or RedisProcessStatusReader(
        os.environ.get("GSVIBE_REDIS_URL", DEFAULT_REDIS_URL),
        os.environ.get("GSVIBE_REDIS_PREFIX", DEFAULT_REDIS_PREFIX),
    )

    @asynccontextmanager
    async def lifespan(_app):
        yield
        if owns_reader:
            await status_reader.close()

    application = FastAPI(title="GoldSrc VibeSignatures Process API", version="1.0.0", lifespan=lifespan)
    application.state.status_reader = status_reader
    application.state.sse_block_ms = sse_block_ms or _positive_environment("GSVIBE_SSE_BLOCK_MS", 15_000)
    application.state.sse_batch_size = sse_batch_size or _positive_environment("GSVIBE_SSE_BATCH_SIZE", 100)
    origins = _origins_from_environment() if cors_origins is None else cors_origins
    if "*" in origins:
        raise ValueError("GSVIBE_API_CORS_ORIGINS cannot contain '*'; configure exact origins")
    if origins:
        application.add_middleware(
            CORSMiddleware, allow_origins=origins, allow_methods=["GET"], allow_headers=["Last-Event-ID"]
        )
    private_network = (
        _boolean_environment("GSVIBE_API_ALLOW_PRIVATE_NETWORK")
        if allow_private_network is None
        else allow_private_network
    )
    if private_network and origins:
        application.add_middleware(PrivateNetworkAccessMiddleware, allowed_origins=origins)
    application.add_exception_handler(RedisStatusReaderUnavailable, _unavailable_handler)
    application.add_exception_handler(RedisStatusDataError, _data_error_handler)
    application.add_api_route("/healthz", lambda: {"status": "ok"}, response_model=HealthResponse)

    async def ready():
        await status_reader.ping()
        return {"status": "ready"}

    application.add_api_route("/readyz", ready, response_model=HealthResponse)
    application.include_router(router)
    return application


app = create_app()


if __name__ == "__main__":
    uvicorn.run(
        "process_api:app",
        host=os.environ.get("GSVIBE_API_HOST", "127.0.0.1"),
        port=int(os.environ.get("GSVIBE_API_PORT", "8000")),
    )
