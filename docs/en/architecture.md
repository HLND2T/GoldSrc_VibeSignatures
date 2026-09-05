[Back to README](../../README.md) | [中文](../zh-CN/architecture.md)

# Architecture

## Data flow

```text
download.yaml + configs/<tag>.yaml
  -> depots/<basepath>
  -> bin/<tag>/<module>/<binary>
  -> validated analysis DAG
  -> versioned stage/job/task execution plan
  -> bin_artifacts/<tag>/<module>/<symbol>.<platform>.yaml (Git truth)
  -> release-only immutable candidate
  -> gamesymbols/<tag>.yaml + gamesymbols/<tag>.metadata.yaml (bundle)
  -> gamesymbols_json.py deterministically derives browser JSON datasets + index (schema 3/4)
  -> packs the single all-in-one gamesymbols-<version>.7z

RunRequest -> Redis Stream -> single-concurrency scheduler -> analyzer
  -> ProcessEvent + heartbeat -> Redis state/streams
  -> read-only API/SSE -> React process dashboard

release-derived JSON datasets + index -> Vite relay plugin
  -> append-only pages-snapshots archive -> GitHub Pages Symbol Explorer

exact source + bin gitlink + bin_artifacts -> analyze all game versions
  -> release bundle + canonical manifest + SHA256SUMS
  -> hosted verify -> protected publish-release -> GitHub Release

trusted PR plan + cache_mode=warm evidence
  -> probe/publish exact generation -> canonical selection -> strict restore
  -> strict no-save selected-node analysis -> validated clean
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
reporter. MCP list preflight results are cached per Agent executable, server, and normalized MCP endpoint (success only).

Raw old-YAML copying is disabled because copying address-bearing artifacts can preserve stale addresses. Automatic
old-version discovery is restricted to an older build in the same game family and is disabled by `major_update: true`.
The analyzer passes a new-output-to-old-YAML map to the Preprocessor so a skill-specific script can relocate signatures
through MCP and rebuild addresses. The shared GoldSrc x86 helper preserves the CS2 Finder API for function/vfunc,
global, patch, struct-member, primary/ordinal vtable, inherited slot, xref filtering, and validated LLM fallback.

The binary is validated as 32-bit I386 before work, and the opened database identity is checked against its path,
platform metadata, and hashes. In line with the CS2 runtime contract, analysis does not add a repeated binary-mutation
guard after each skill. Pending work allocates a free local port and starts one owned `idalib-mcp` lifecycle per binary on
`127.0.0.1:<dynamic-port>` (the fixed `13337` is no longer reserved); for each module/platform binary, the analyzer checks
the IDB lock and port, starts the supervisor, waits for the MCP contract, binds the exact active database, validates
survey identity, allows one health recovery, and performs targeted owned-worker shutdown plus port release. The verified
runtime endpoint is injected into Agent fallback runs as an invocation-scoped MCP override, so each Agent connects the
exact owned lifecycle for its binary. Every
Preprocessor call binds that binary/database and receives a strictly parsed image base. Preprocessor and Agent outputs
pass the same YAML, symbol-schema, and current-IDB address validator. `-ida_args` is supported while `-rename` remains
deferred.

`-skip_pp` bypasses the single Preprocessor and runs Agent Skills directly. `-skip_error` allows later
module/platform/skill work to continue after runtime failures, while configuration and DAG contract failures remain
fatal and any recorded runtime failure still produces a nonzero final exit status.

## Warm IDB cache boundary

`idb_cache.py` provides a local immutable-generation cache for neutral IDA databases. A new schema-1 key binds exact
binary path/bytes, the IDA kernel version, and the canonical warm-worker source contract. `normalized_ida_args` remains
an empty compatibility field; readers still validate old schema-1 identities containing the former full runtime and
non-empty arguments without projecting or rewriting them. A generation contains an exact cached binary plus the complete
allowed `.i64`/`.idb` primary and side-file inventory; active lock files are always rejected.

Publication verifies an incoming tree before atomic rename and updates `READY.json` only afterward. READY is a probe
hint, not a consumer authority: restore always binds an exact generation, key, and manifest SHA-256. READY writes are
idempotent — identical canonical bytes are not re-replaced, and the JSON writer itself uses a UUID temporary file plus
bounded Windows sharing-violation retry so a concurrent reader cannot leave a half-written or PID-clobbered file.
Restore rejects reparse points, path escapes, case collisions, stale workspace binaries, tampered manifests/payloads,
and active locks. The `restored_strict` lifecycle policy never invalidates or cold-rebuilds a mismatched restored
database and can disable success saves so selected-node modifications never flow back into the immutable generation.

Selection primitives are shared. `idb_cache_selection.py` owns the canonical entry shape, coverage/identity validation,
SHA-256 evidence files, short locked probe/finalize phases, lock-free workspace warm, and locked exact restore; the PR and
release workflows build their own top-level documents (`plan_sha256`/`merge_sha` vs `source_sha`/`bin_commit`) but cannot
drift on the generation contract. `idb_cache_locks.py` owns the cross-process producer and tag locks. Only explicit lock
contention is polled indefinitely; storage, permission, handle, and unknown I/O failures stop immediately.

The trusted PR plan carries the invariant evidence field `cache_mode=warm`. Every analysis route splits the producer into
the reusable `warmup-idb` job and turns `analyze-self-hosted` into a pure consumer: it downloads the canonical selection,
verifies it against its own checkout and pinned runtime, restores the exact generations under the tag lock, and runs
strict selected-node analysis. The release build uses the same producer (`scope: release-all`) and a structurally
identical consumer. There is no analysis-side rebuild/save route. A repository-level Actions concurrency group serializes
the one official producer, while a persisted producer-only SMB lock also excludes direct producers. On a miss, the
canonical Python executable probes its IDA version and starts one bare-idalib process per binary under a bounded
`ThreadPoolExecutor`; no MCP port is used. Worker timeout follows kill/wait-before-cleanup, failures affect only the owned
database set, siblings finish, and any failure prevents group publication. Optional aggregate memory admission uses one
process-level Windows Job controller across groups and a fresh gate/baseline for each group.

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

The writer emits schema 6 with config digest v2, analysis-output contract version 2, UTC publication time, canonical
file payloads, and path-independent SHA-256/MD5/CRC32/CRC64/size metadata for every configured binary. The reader accepts schemas 1–6; schema 5 retains its required legacy binary `path`.
Restore and verification reject links, path escapes, undeclared YAML, missing required YAML, non-canonical bytes, and
contract drift.

The candidate session binds the canonical snapshot and alias-metadata companion hashes, filesystem identities, and pair
identity. Pair publication into release staging is journaled and recoverable. The verified release bundle is the external
candidate boundary; a release publication requires the guarded `json` step (`mark -step json`), while the gamedata
consistency gate (`mark -step gamedata`) is enforced by PR validation and `update_gamedata.py`. Candidate sessions do not
contain a C++ test step.

Canonical gamedata is derived only from the guarded candidate inventory (`update_gamedata.py` / PR validation), never the
Git index. Each tag has a self-excluding canonical manifest that binds snapshot/config/generator identities and the exact
declared payload files; an empty generator set therefore still has one verifiable output. gamedata is no longer a Release
artifact.

## Release provenance boundary

The release build force-rebuilds every configured artifact into a fresh external root and compares exact bytes with Git
`bin_artifacts`. It then generates snapshots, metadata, browser JSON datasets (`mark -step json`), the single all-in-one
`gamesymbols-<version>.7z`, a canonical Release manifest, and `SHA256SUMS`. The self-hosted job is read-only; a
GitHub-hosted job verifies the closed bundle against the exact source and Git blobs, independently re-deriving the JSON
and comparing it byte-for-byte with the bundle. The protected `publish-release` job is the only `contents: write` job in
`release-build.yml`.
It creates or resumes a matching draft, refuses tag/asset drift and overwrite, verifies remote name/size/hash, then
publishes. Published versions are immutable; changed content requires a new version.

## API, dashboard, and immutable Pages assets

`process_api.py` is read-only. It provides health/readiness, run pagination, graph/snapshot/task/event views, and SSE with
`Last-Event-ID`. The default live cursor is anchored to a concrete Stream ID; an expired cursor, including one overtaken by
trimming during a live connection, returns a reset contract that points back to the atomic snapshot. The service binds
`127.0.0.1` by default, has no built-in authentication, restricts CORS to configured origins, and permits browser
private-network preflights only by explicit opt-in.

The React dashboard displays run lists, graph/list views, task details, status filters, live SSE updates, and a static
Symbol Explorer. Symbol snapshots use `<family-build>` tags, are grouped by family, and sort builds numerically descending.
The release pipeline deterministically derives the exact UTF-8 content-addressed JSON datasets plus index schema v4 in
Python from the schema-6 snapshot and schema-1 metadata companion; the Vite plugin relays those bytes without re-deriving
and never reads live config aliases. The deployment workflow downloads and extracts `gamesymbols-*.7z` to obtain the same
JSON, preserves every digest on an append-only `pages-snapshots` branch, and verifies current, archived, and deployed CDN
bytes. That branch is a non-authoritative presentation mirror derived only from published Releases; it is never source
or release truth. GitHub Pages hosts only static assets; it does not host the Process API.

## Current exclusions and deferrals

Plan preview remains removed; the internal builder serves real execution only. Generic Source2 vcall finding, Source2
RTTI/dispatch semantics, remote API hosting, C++ layout analysis, automatic version bumping, broad production signature
coverage, and target-specific generators remain excluded. Commercial IDA verification still requires a configured local
or self-hosted runner. Current production finder coverage is declared in the game-version configs rather than maintained as a separate documentation inventory.
