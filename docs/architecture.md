# Architecture

## Data flow

```text
download.yaml + configs/<tag>.yaml
  -> depots/<basepath>
  -> bin/<tag>/<module>/<binary>
  -> validated analysis DAG
  -> versioned stage/job/task execution plan
  -> bin/<tag>/<module>/<symbol>.<platform>.yaml
  -> immutable candidate
  -> gamesymbols/<tag>.yaml
  -> SymbolStore -> strict gamedata generator

RunRequest -> Redis Stream -> single-concurrency scheduler -> analyzer
  -> ProcessEvent + heartbeat -> Redis state/streams
  -> read-only API/SSE -> React process dashboard

gamesymbols/<family-build>.yaml -> Vite asset plugin
  -> content-addressed JSON + index v4
  -> append-only pages-snapshots archive -> GitHub Pages Symbol Explorer
```

`analysis_planner.py` is the single source for module, symbol, artifact-path, and DAG validation. Snapshot contracts
reuse it, so an output accepted by analysis cannot silently acquire different ownership at publication time.
Outputs are module-local. Inputs may reference a sibling module with `../<module>/<artifact>`; the planner normalizes
both producer and consumer to one game-root-relative owner path and creates a real cross-module edge.

Config symbols use `name + category` and reject `type/kind`. Artifact payloads use category-specific identities
(`func_name`, `gv_name`, `patch_name`, `vtable_class`, or `struct_name/member_name`) and reject generic
`name/type/kind`. Payload identity is deliberately not compared with config symbol identity.

## Analysis layers

For each DAG node, `ida_analyze_bin.py` currently attempts two executable layers in order:

1. Run and process-cache `ida_preprocessor_scripts/<skill>.py` through a bound IDA MCP session. A script receives LLM
   runtime configuration only when it explicitly declares `llm_config`, and returns `success`, `absent_ok`, `no_script`,
   or `failed`.
2. Run the configured Agent skill with bounded retries when fallback is required.

The Agent runner validates per-CLI model arguments, keeps Claude/OpenCode retry sessions stable, injects the Codex
developer prompt, drains stdout/stderr concurrently, and emits attempt-level structured diagnostics through the local
reporter. MCP list preflight results are cached per Agent executable and server.

Raw old-YAML copying is disabled because copying address-bearing artifacts can preserve stale addresses. Automatic
old-version discovery is restricted to an older build in the same game family and is disabled by `major_update: true`.
The analyzer passes a new-output-to-old-YAML map to the Preprocessor so a skill-specific script can relocate signatures
through MCP and rebuild addresses. The shared GoldSrc x86 helper preserves the CS2 Finder API for function/vfunc,
global, patch, struct-member, primary/ordinal vtable, inherited slot, xref filtering, and validated LLM fallback.

The binary is validated as 32-bit I386 before work, and the opened database identity is checked against its path,
platform metadata, and hashes. In line with the CS2 runtime contract, analysis does not add a repeated binary-mutation
guard after each skill. For each module/platform binary with pending work, the analyzer owns one `idalib-mcp` lifecycle: it checks
the IDB lock and port, starts the supervisor, waits for the MCP contract, binds the exact active database, validates
survey identity, allows one health recovery, and performs targeted owned-worker shutdown plus port release. Every
Preprocessor call binds that binary/database and receives a strictly parsed image base. Preprocessor and Agent outputs
pass the same YAML, symbol-schema, and current-IDB address validator. `-ida_args` is supported while `-rename` remains
deferred.

`-skip_pp` bypasses the single Preprocessor and runs Agent Skills directly. `-skip_error` allows later
module/platform/skill work to continue after runtime failures, while configuration and DAG contract failures remain
fatal and any recorded runtime failure still produces a nonzero final exit status.

## Process reporting and scheduling

The validated analysis DAG remains the only planning source. `build_process_execution_plan()` projects it into an
immutable schema-v1 graph with stable stage, job, task, layer, edge, and auxiliary-node identifiers. Direct analyzer
execution and queued execution therefore report the same graph.

`ProcessEvent` defines run/task state machines, phases, stable reasons, payloads, occurrence time, and revision ordering.
The reporter lifecycle is `initialize_run`, `emit`, `heartbeat`, `finalize_run`, `flush`, and `close`. The analyzer wraps
backends with `BestEffortProcessReporter`, so monitoring failures never change analysis results. The console backend emits
the current JSONL protocol; the Redis backend atomically persists run/task views and appends events under
`gsvibe:analysis:v1`. No legacy event API or format is retained.

`RedisRunQueue` stores validated minimal `RunRequest` objects in a consumer-group Stream. The scheduler runs one analyzer
at a time under a renewable global Redis lease, constructs argv without shell interpolation, injects reporter/run-ID
environment values, honors live heartbeats, uses `XAUTOCLAIM` for stale pending entries, prevents terminal-run replay, and
derives a final status from the child exit code when the analyzer did not persist one. Scheduler terminal fallback
atomically aborts every unfinished task and recomputes the summary before appending the terminal run event.

## Snapshot boundary

The writer emits schema 5 with config digest v2, analysis-output contract version 2, UTC publication time, canonical
file payloads, and SHA-256/MD5/CRC32/CRC64/size metadata for every configured binary. The reader accepts schemas 1–5.
Restore and verification reject links, path escapes, undeclared YAML, missing required YAML, non-canonical bytes, and
contract drift.

The candidate manifest records the canonical candidate hash and filesystem identity. Publication is an atomic replace
and requires the guarded `gamedata` step. Candidate sessions do not contain a C++ test step.

## API, dashboard, and immutable Pages assets

`process_api.py` is read-only. It provides health/readiness, run pagination, graph/snapshot/task/event views, and SSE with
`Last-Event-ID`. The default live cursor is anchored to a concrete Stream ID; an expired cursor, including one overtaken by
trimming during a live connection, returns a reset contract that points back to the atomic snapshot. The service binds
`127.0.0.1` by default, has no built-in authentication, restricts CORS to configured origins, and permits browser
private-network preflights only by explicit opt-in.

The React dashboard displays run lists, graph/list views, task details, status filters, live SSE updates, and a static
Symbol Explorer. Symbol snapshots use `<family-build>` tags, are grouped by family, and sort builds numerically descending.
The Vite plugin turns tracked schema-5 YAML into exact UTF-8 content-addressed JSON plus index schema v4. The deployment
workflow preserves every digest on an append-only `pages-snapshots` branch and verifies current, archived, and deployed
CDN bytes. GitHub Pages hosts only static assets; it does not host the Process API.

## Current exclusions and deferrals

Plan preview remains removed; the internal builder serves real execution only. Generic Source2 vcall finding, Source2
RTTI/dispatch semantics, remote API hosting, C++ layout analysis, automatic version bumping, broad production signature
coverage, and target-specific generators remain excluded. Commercial IDA verification still requires a configured local
or self-hosted runner. The first production finder is `svencoop-10257/engine/R_RenderView`.
