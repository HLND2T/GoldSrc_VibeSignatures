[Back to README](../../README.md) | [中文](../zh-CN/process-monitoring.md)

# Process reporting, scheduling, and dashboard

## Redis process reporting

Redis process reporting is optional. Set:

```text
GSVIBE_PROCESS_REPORTER=redis
GSVIBE_REDIS_URL=redis://127.0.0.1:6379/0
```

Alternatively, pass `-process_reporter=redis`, `-redis_url=...`, and the optional `-redis_prefix=...` arguments to the Analyzer.

The Reporter publishes the immutable execution graph, current Run/Job/Task snapshots, an event Stream, atomic summary counters, and a TTL heartbeat. Temporary Redis failures do not change the Analyzer result; the latest local snapshots are replayed after reconnection.

## Scheduler

Queue an Analyzer run, then start the single-concurrency worker:

```bash
uv run python process_scheduler_cli.py submit --gamever cstrike-10210 --agent claude
uv run python process_scheduler_cli.py run
```

The Redis Stream consumer group preserves FIFO order, recovers pending entries after Scheduler restarts, and does not relaunch a recovered Run while its Analyzer heartbeat is still alive. Queue payloads are validated fields rather than executable shell commands. The request contract is intentionally minimal: `run_id`, `gamever`, `platforms`, `modules`, `skill_filter`, `agent`, and `created_at`; the scheduler controls its own argv and environment. Scheduler recovery atomically aborts unfinished tasks and recomputes the run summary.

## Read-only progress API

Start the API locally:

```bash
uv run uvicorn process_api:app --host 127.0.0.1 --port 8000
```

The service exposes `/healthz`, `/readyz`, run list/detail, execution graph, snapshot, task, event-page, and SSE stream routes below `/api/v1`. SSE supports `Last-Event-ID` and emits a reset event when the retained Redis cursor is too old, including when trimming overtakes a live connection; the default live cursor is anchored to a concrete Stream ID before blocking.

The service binds to localhost by default and has no built-in authentication. Put external deployments behind an authenticated reverse proxy. Configure browser origins with `GSVIBE_API_CORS_ORIGINS`, tune SSE through `GSVIBE_SSE_BLOCK_MS` and `GSVIBE_SSE_BATCH_SIZE`, and use `/healthz` and `/readyz` for liveness and Redis readiness.

## Dashboard and Symbol Explorer

The React dashboard in `pages/` consumes this API and also provides a static Symbol Explorer. Build with:

```bash
cd pages
npm ci
npm run build
```

GitHub Pages publishes only the static `pages/dist` artifact; it does not host the API/SSE process — the browser connects to the Process API on the machine that runs it. For a public Pages origin that connects to FastAPI on the same browser machine, add the exact origin to `GSVIBE_API_CORS_ORIGINS` and set `GSVIBE_API_ALLOW_PRIVATE_NETWORK=true`.

The `pages-snapshots` branch is append-only and stores every content-addressed `<family-build>.<sha256>.json` snapshot. `npm run verify:gamesymbols` and the deployment job verify exact response bytes and digests.
