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
Bounded admission combines `GSVIBE_ANALYSIS_MAX_CONCURRENCY` with the aggregate process-tree memory gate from
`analysis_memory.py` (reusing `warmup_memory` primitives, plus host headroom from `GlobalMemoryStatusEx` on Windows or
`/proc/meminfo` on POSIX). The gate's enforcement tier is a Windows Job, a Linux cgroup v2 child cap, or — where no
cgroup is delegated — per-worker limits with reservation-based admission.

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
  in-flight worker. An **unconfirmed** exit (kill command failed or wait timed out) is its own
  `worker_cleanup_failed` outcome: keep the worker tracked, keep its gate slot reserved, and stop all admission
  even under -skip_error — releasing the slot invites over-admission behind a tree that still holds memory. The
  kill command itself needs an explicit timeout, not just the exit wait. A **failed kill step** (exception,
  non-zero command exit, command timeout) stays a cleanup failure **even when the root exits afterwards**: the
  root's exit proves nothing about descendants that were already reparented, so check the command's return code
  and never let a successful root wait() launder a failed tree kill. Every member's signal failure counts — on
  POSIX only `ProcessLookupError` is benign (a missing pid is positive evidence that member exited); a
  PermissionError on a single descendant keeps the whole teardown unconfirmed.
- Validation should encode the real invariant, not a proxy: rejecting "binary in multiple work items" broke the
  legal cross-phase reopen (parallel item then serial segment on the same binary). Validate node uniqueness plus
  "no binary in two overlapping parallel items" instead.
- Production wiring must pass its **default probes explicitly** — an optional constructor parameter defaults to
  `None` and silently disables the check (`default_host_memory_probe()` now feeds the authority).

## POSIX memory guard review lessons (PR #206)

- Trigger: a worker's resident watchdog fires but IDA descendants remain alive, or unrelated process churn makes
  the measured tree usage drop to zero.
- Root cause: the watchdog runs inside the root it kills; ascending PID order can kill that root first, and PID
  wrap means numeric order cannot encode ancestry. A single exception around the whole `/proc` scan also discards
  valid samples when any unrelated process exits.
- Correct approach: snapshot descendants before ancestors, signal the root last, and handle read/parse failures
  per PID. Install degraded limits on direct analyzers as well as batch workers; reuse one watchdog for sequential
  direct tags. Clear the worker VAS variable outside the degraded tier so inherited configuration cannot enable it.
- Verification: `tests.test_posix_memory` includes PID-wrap ordering, partial `/proc` samples and a real Linux
  self-watchdog child-exit test; analysis memory/batch tests cover direct entry and tier-specific worker environments.
- Scope: Linux analysis/warmup resident watchdogs and analyzer memory-limit wiring.

## Verification

`uv run python -m unittest tests.test_analysis_batch tests.test_analysis_memory tests.test_analysis_planner`
covers classification/closure/segmentation, the result contract, scheduler gating/barrier/stop-admission/timeout,
memory parsing/host-headroom, and the locked dynamic-port retry. Real-runner concurrency/memory/cancel/license
evidence is still required before raising the production Environment concurrency above 1.

## Selected-node batches (issue #81)

- Trigger: a PR affects multiple tags but its per-tag IDA calls serialize the expensive work.
- Constraint: classify complete DAGs before filtering selections; otherwise an unselected cross-binary producer can erase a serial-tail dependency. Structural planning may defer external file checks, but selected external inputs must all pass after materialization and before any worker starts; selected predecessors are allowed to produce intermediate inputs later.
- Correct approach: `-batch_selection` consumes schema-versioned generic tag/node selections, never a PR plan. Strictly reject invalid entries and conflicting selectors. Reuse one batch scheduler, shared analysis limits, global success barrier, exact restored/no-save workers and serial postprocessing. `-validate_selection_only` validates the full selection/DAG before materialization.
- Diagnostics: unique invocation/task paths, redacted per-worker logs, atomic structured summary and scheduler events (including cancelled/not-executed/cleanup failure); PR upload only allowlists logs and summary, never worker requests or IDBs.
- Verification: `tests.test_analysis_batch` covers exact selection, deferred/external inputs, CLI conflicts, real lightweight subprocess diagnostic capture on success/failure, and existing scheduler timeout/cancellation/cleanup contracts. Real IDA behavior is distinct from these fixtures.
- Scope: selected PR analysis and the shared full-analysis coordinator. Single-tag public selection behavior remains on its existing path.
- Activation decision (2026-09-08): user explicitly requested immediate use of existing concurrency and waived the concurrency-1/2 comparison. Do not claim measured speedup or substitute this authorization for real-IDA evidence. Rollback keeps the batch entry and sets concurrency to 1.

## Windows worker Job teardown (2026-09-24)

- Trigger: batch worker timeout or cancellation previously invoked `taskkill /F /T` from `analysis_batch.py`.
- Root cause / constraint: the existing aggregate memory Job contains the coordinator itself, so terminating it would kill the coordinator and sibling workers. A PID tree walk can also lose descendants after the root exits.
- Correct approach: each Windows batch worker gets a nested Job with `KILL_ON_JOB_CLOSE`. The worker waits for a coordinator-created start marker before analysis begins; the coordinator assigns its process to the Job before creating that marker. Timeout/cancellation calls `TerminateJobObject` and waits for the Job's active-process count to reach zero before releasing the memory slot. Normal root exit closes the Job handle, which terminates any remaining descendants. An unassigned Windows batch worker fails closed. The external idalib-mcp launcher has a separate tree-stop path and still uses `taskkill`.
- Verification: `tests.test_analysis_batch` checks Job teardown, failure handling, missing-Job behavior, and a real Windows worker/descendant pair with a surviving sibling. Run with `uv run python -m unittest tests.test_analysis_batch tests.test_analysis_memory tests.test_warmup_concurrency tests.test_analysis_planner`.
- Scope: Windows analysis batch process ownership; the aggregate memory Job and POSIX tree cleanup remain as before.