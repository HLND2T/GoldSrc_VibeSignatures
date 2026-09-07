---
title: process-reporting-and-scheduler
type: architecture
permalink: goldsrc-vibesignatures/process-reporting-and-scheduler
tags:
- process
- reporter
- scheduler
- redis
- api
- dashboard
---

# Process reporting, scheduling, and read-only API

## Overview

The validated analysis DAG is the only planning source. `build_process_execution_plan()` projects it into an immutable
schema-v1 graph with stable stage/job/task/layer/edge/auxiliary-node identifiers, so direct analyzer execution and queued
execution report the same graph.

## ProcessEvent and the reporter lifecycle

`ProcessEvent` defines run/task state machines, phases, stable reasons, payloads, occurrence time, and revision ordering.
The reporter lifecycle is `initialize_run`, `emit`, `heartbeat`, `finalize_run`, `flush`, `close`. The analyzer wraps
backends with `BestEffortProcessReporter`, so monitoring failures never change analysis results. The console backend emits
the current JSONL protocol; the Redis backend atomically persists run/task views and appends events under
`gsvibe:analysis:v1`. No legacy event API or format is retained.

## Redis scheduler

`RedisRunQueue` stores validated minimal `RunRequest` objects (`run_id`, `gamever`, `platforms`, `modules`,
`skill_filter`, `agent`, `created_at`) in a consumer-group Stream. The scheduler:

- runs one analyzer at a time under a renewable global Redis lease;
- constructs argv without shell interpolation and injects reporter/run-ID environment values;
- honors live heartbeats (a recovered Run is not relaunched while its Analyzer heartbeat is alive);
- uses `XAUTOCLAIM` for stale pending entries after scheduler restarts;
- prevents terminal-run replay and derives a final status from the child exit code when the analyzer did not persist one;
- on terminal fallback atomically aborts every unfinished task and recomputes the summary before appending the terminal
  run event.

Temporary Redis failures do not change the Analyzer result; the latest local snapshots are replayed after reconnection.

## Read-only Process API

`process_api.py` is read-only and exposes `/healthz`, `/readyz`, run list/detail, execution graph, snapshot, task,
event-page, and SSE routes below `/api/v1`. SSE supports `Last-Event-ID` and emits a reset event when the retained Redis
cursor is too old, including when trimming overtakes a live connection; the default live cursor is anchored to a concrete
Stream ID before blocking. The service binds `127.0.0.1` by default, has no built-in authentication (put external
deployments behind an authenticated reverse proxy), restricts CORS to `GSVIBE_API_CORS_ORIGINS`, and permits browser
private-network preflights only through explicit `GSVIBE_API_ALLOW_PRIVATE_NETWORK=true`.

## Dashboard and Pages mirror

The React dashboard (`pages/`) shows run lists, graph/list views, task details, status filters, live SSE updates, and a
static Symbol Explorer. GitHub Pages hosts only the static `pages/dist` artifact; it never hosts the Process API — the
browser connects to the API on the machine that runs it. Symbol snapshots use `<family-build>` tags, group by family,
and sort builds numerically descending. `pages-snapshots` is an append-only, non-authoritative presentation mirror
derived only from published Releases; it is never source or release truth. See
[[Immutable alias metadata companion]] and [[Release bundle publication and recovery]] for the derived-data boundary.

## Validation

Unit and integration coverage: run/task state machines, scheduler gating/lease/heartbeat/recovery/terminal-fallback,
Redis stream semantics, SSE reset contract, API read-only guarantees, and BestEffort isolation. Redis coverage is
exercised by the `redis-integration` test group (see [[test 文件必须登记到测试分组]]).
