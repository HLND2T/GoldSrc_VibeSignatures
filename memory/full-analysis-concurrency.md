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

## Verification

`uv run python -m unittest tests.test_analysis_batch tests.test_analysis_memory tests.test_analysis_planner`
covers classification/closure/segmentation, the result contract, scheduler gating/barrier/stop-admission/timeout,
memory parsing/host-headroom, and the locked dynamic-port retry. Real-runner concurrency/memory/cancel/license
evidence is still required before raising the production Environment concurrency above 1 (see
`docs/plans/full-analysis-concurrency-migration.md` §15).
