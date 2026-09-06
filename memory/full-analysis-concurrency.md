---
title: full-analysis-concurrency
type: note
permalink: goldsrc-vibesignatures/full-analysis-concurrency
---

# Full analysis bounded concurrency

## Overview

`ida_analyze_bin.py -allgamever -force_all` runs through the two-phase batch coordinator in `analysis_batch.py`:
per-tag complete node DAGs are classified once (cross-binary edge targets plus downstream closure go to the serial
tail queue; everything else becomes per-binary parallel work items), each work item is an internal worker process
launched with the `--internal-batch-worker` request file, and a strict success barrier separates the phases.
Bounded admission combines `GSVIBE_ANALYSIS_MAX_CONCURRENCY` with the aggregate Job memory gate from
`analysis_memory.py` (reusing `warmup_memory` primitives, plus `GlobalMemoryStatusEx` host headroom).

## Key lessons

- The scheduler's memory gate must be **non-blocking** (`try_admit` returning a wait reason). A blocking
  `wait_for_launch` deadlocks the single-threaded coordinator: worker slots are only released after the main loop
  polls exited workers, which cannot happen while admission blocks. `AnalysisMemoryGate` therefore exposes both
  `try_admit` (scheduler loop) and `wait_for_launch` (compat).
- Dynamic MCP ports must be allocated under the cross-process startup lock in `mcp_startup.py` (RUNNER_TEMP),
  and the lock must cover only allocate/spawn/bind-confirm; full IDA readiness stays outside the lock or parallel
  analyzers serialize their whole IDA startup. `start_dynamic_idalib_mcp` retries with a fresh port when a port is
  stolen or never bound.
- Worker results are a control-plane contract (exact key set, identity, precise ordered `node_ids`, summary
  consistency, zero exit cannot mask failed nodes). Terminal node statuses are captured in-process by
  `_RecordingProcessReporter` mapping process-plan task IDs back to planner node IDs; the coordinator never parses
  worker logs.
- Secrets (LLM API key) travel only through the child environment; the request JSON and result JSON carry none.

## Review-fix lessons (PR #67)

- Cross-process identity contracts need **one composition rule shared by both sides**: the coordinator stamped
  `<batch_run_id>-<work_item_id>` into worker requests but validated results against the bare batch run id, so
  every conforming result was rejected. `work_item_run_id()` is now the single source for both paths.
- Any identifier that reaches a **filesystem name or a reporter run id must be unique across the whole batch**,
  not per tag: per-tag `parallel-0000` numbering made concurrent tags overwrite each other's request/result files.
  `build_batch_schedule` renumbers both phases globally.
- Batch success must include **worker-level failure**, not just node counts: a worker can report status=failed
  (cleanup/lifecycle failure) while every node exited successfully; `outcome.succeeded` therefore also requires
  `failure_reason is None`.
- A scheduler that owns child processes needs an **exception-path teardown**: wrap scheduling in
  `except BaseException`, sweep active workers with `taskkill /F /T` (or a POSIX /proc walk + SIGKILL, snapshot
  descendants before touching the root and kill deepest-first), confirm exit before releasing the memory-gate
  slot, then re-raise. The tree kill must run **while the root is alive and unconditionally**: Windows
  `terminate()` hard-kills only the root, and descendants are reparented once the root exits so they can no
  longer be attributed to the worker — a root exit never proves the tree exited. The child pid stays reserved
  until `wait()` reaps it, so an unreaped pid cannot be reused by an unrelated process. Workers retire from the
  active list only on completed paths: a `finally` removal runs before the cancellation sweep and leaks the
  in-flight worker.
- Validation should encode the real invariant, not a proxy: rejecting "binary in multiple work items" broke the
  legal cross-phase reopen (parallel item then serial segment on the same binary). Validate node uniqueness plus
  "no binary in two overlapping parallel items" instead.
- Production wiring must pass its **default probes explicitly** — an optional constructor parameter defaults to
  `None` and silently disables the check (`default_host_memory_probe()` now feeds the authority).

## Verification

`uv run python -m unittest tests.test_analysis_batch tests.test_analysis_memory tests.test_analysis_planner`
covers classification/closure/segmentation, the result contract, scheduler gating/barrier/stop-admission/timeout,
memory parsing/host-headroom, and the locked dynamic-port retry. Real-runner concurrency/memory/cancel/license
evidence is still required before raising the production Environment concurrency above 1 (see
`docs/plans/full-analysis-concurrency-migration.md` §15).
