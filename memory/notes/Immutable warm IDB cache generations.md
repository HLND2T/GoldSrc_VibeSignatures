---
title: Immutable warm IDB cache generations
type: architecture
permalink: goldsrc-vibesignatures/notes/immutable-warm-idb-cache-generations
tags:
- ida
- idb-cache
- self-hosted
- security
---

# Immutable warm IDB cache generations

## Overview

Warm IDB cache is a rebuildable performance layer for neutral databases created after loader/auto-analysis and before any project finder, Preprocessor, or Agent mutation. It is never analysis or release truth.

## Responsibilities
- Bind binary path/size/SHA-256, the non-empty IDA kernel version, an empty compatibility-only `normalized_ida_args`, and the canonical three-file warm-worker source contract.
- Preserve exact schema-1 reads for legacy seven-field runtime identities and non-empty historical IDA arguments without projecting or rewriting them.
- Warm one binary per bare-idalib process with bounded group concurrency and optional aggregate Windows Job memory admission.
- Publish immutable generations through verified `.incoming-*` directories and atomic rename.
- Record the complete allowed `.i64`/`.idb` primary and side-file inventory; never publish active lock files.
- Restore only an exact generation selected by cache key and manifest SHA-256.
- Retain READY plus the newest three generations, with minimum-age protection for other generations.

## Involved Files & Symbols

- `idb_warm_worker.py` — `ida_kernel_version()`, `warm_binary()`
- `idb_cache.py` — `warm_group()`, `_run_one_worker()`, `publish_generation()`
- `ida_database_paths.py` — `database_cleanup_paths()`
- `idb_cache_locks.py` — `producer_lock()`, `tag_lock()`, `exclusive_file_lock()`
- `idb_cache_selection.py` — `prepare_selection_entries()`, `restore_selection_entries()`
- `warmup_memory.py` — `ProducerMemoryOwner`, `MemoryLaunchGate`, `WindowsJobMemoryController`
- `idb_cache_release.py` / `idb_cache_workflow.py` — release-all and bound-plan producers/consumers
- `.github/workflows/warmup-idb.yml` — canonical IDA Python binding and producer configuration

## Architecture
`ida_database_paths.py` owns the primary/side/lock and complete failure-cleanup path contract. `idb_warm_worker.py` is the only worker executable: it imports `idapro` only inside `--print-ida-version` or `run -binary`, then uses bare idalib to open, wait for analysis, save, and close one database. `auto_wait()` false is a failure and never saves.

`idb_cache.py` owns schema-1 identity, key, manifest, READY, concurrent `warm_group`, publish, probe, verify, restore, and prune. It binds every worker and the version probe to one validated IDA Python executable, uses `ThreadPoolExecutor` for per-binary processes, and requires every process to exit successfully with a valid database set before publication. Worker timeout is explicit `kill -> wait -> owned-file invalidation`; siblings are not cancelled.

`idb_cache_locks.py` owns a repository-wide producer-only SMB byte-range lock plus per-tag locks. High-level production is `short locked probe -> unlocked warm -> short locked re-probe/optional publish/verify/prune`; consumers retain `locked exact verify -> restore`. Only explicit lock contention is polled indefinitely. Storage, permission, handle, and unknown I/O errors fail closed.

`warmup_memory.py` owns the optional process-level Windows Job controller. The first miss binds at most one controller per producer process, every miss group takes a fresh baseline and launch gate, and the bound Job handle remains strongly owned until process exit.
## Strict consumer

`IdaMcpLifecycle(database_policy="restored_strict", save_on_success=False)` requires an existing restored database. Identity mismatch fails without invalidation or cold rebuild. Successful selected-node changes are not saved back, so the immutable generation remains neutral.

## Workflow integration
The schema-2 trusted PR plan carries the invariant evidence field `cache_mode=warm`; it is not user-selectable. Every official analysis route uses the reusable `warmup-idb.yml` producer. The workflow canonicalizes one PATH-resolved IDA Python executable, obtains its kernel version through `idb_warm_worker.py --print-ida-version`, and passes that executable to release-all or bound-plan preparation. The producer no longer requires `idalib-mcp` or `IDADIR`; strict consumers still use [[idalib-mcp]] for analysis.

Official producers share the repository-wide Actions concurrency group (`idb-warmup-${{ github.repository }}`, `cancel-in-progress: false`). Official and direct producers also share persisted `idb-cache/.locks/producer.lock`, so a bypass invocation cannot overlap the official producer. Verify/restore never re-read READY. A failed, cancelled, or skipped producer blocks analysis; there is no cold or consumer-side rebuild fallback.

## Concurrent bare-idalib warmup

- **Trigger signal:** A cache-miss group contains several binaries and wall time scales as their serial sum, or a fixed MCP port lock prevents overlapping workers.
- **Root cause / constraints:** idalib owns one open database per process. MCP-port serialization is unnecessary for neutral warming, but immutable group publication, exact selection, producer/tag lock authority, worker ownership, and stale `.id0` safety must remain fail-closed.
- **Correct approach:** Run one canonical bare-idalib worker per binary, bound to the same probed IDA Python executable. Bound concurrency with `IDB_WARMUP_MAX_CONCURRENCY` (default 2). When `IDB_WARMUP_MAX_MEMORY_MIB` is configured, admit through a finite per-task deadline on a reused process-level Job controller; otherwise retain each worker's own memory limit.
- **Failure authority:** Admission, preflight, and spawn failures do not grant failed-worker cleanup authority. After an actual worker starts, only its producer owner may invalidate `database_cleanup_paths()` and only after confirmed process exit. Startup `.id0` remains an active-lock signal. Windows WinError 5/32 deletion retries are bounded.
- **Verification:** Unit tests cover `auto_wait=False`, explicit IDA executable binding, max concurrency, sibling isolation, timeout kill/wait-before-cleanup, stale lock cleanup, transient delete retry, producer/tag lock boundaries, legacy identity reads, and controller reuse. Production activation additionally requires real Windows Job, throughput, and cross-runner SMB3 evidence.
- **Scope:** This changes only producer warming and shared cache identity construction. Consumer `IdaMcpLifecycle(database_policy="restored_strict", save_on_success=False)`, immutable generation payloads, exact restore, and group granularity remain unchanged.

## Cache group granularity and cross-scope reuse

A cache generation is addressed per complete `(tag, platform, binaries[])` identity, not per individual binary. `cache_key()` hashes the canonical identity, including every binary's module, platform, relative path, size, and SHA-256. Probe accepts only an exact key and identity match; generations cannot be partially composed.

`bound-plan` and `release-all` intentionally construct different groups:

- `idb_cache_workflow._selected_binary_groups()` includes only module/platform pairs required by the bound analysis nodes.
- `idb_cache_release.release_binary_groups()` enumerates every configured binary target and groups the full set by tag/platform.

Consequently, a bound-plan generation containing only `engine/hw.dll` does not satisfy a release-all identity containing `engine + client + gameui + server`, even when the engine binary, source tree, bin gitlink, IDA runtime, and warm-worker contract are unchanged. The group cardinality change produces a different cache key and forces an all-or-nothing rebuild for that group.

### Diagnostic signature

- Trigger signal: a nearby bound-plan warmup has many hits, followed by a release-all warmup with many misses.
- Root cause check: compare producer scope and `binaries=N` before investigating corruption. If unchanged singleton groups still reuse old generation names while overlapping groups change from `binaries=1` to `binaries=4`, persisted storage and runtime identity are working; the miss is caused by group identity expansion.
- Verification: confirm source Git tree, bin gitlink, IDA kernel, and warm-worker contract are unchanged; partition release results into unchanged exact groups, same tag/platform with changed binary cardinality, and groups absent from the earlier plan. A second identical release-all run should hit the generations published by the first unless identity or persisted bytes changed.
- Scope: this explains cross-scope cache reuse only. GitHub Actions submodule/uv cache hits, misses, or archive-save failures are independent of `PERSISTED_WORKSPACE/idb-cache`.

Observed example on 2026-09-01:

- Game-symbol PR validation run `33468693517`, job `99733895794`, used bound-plan and reported 13 hits / 0 misses, with one binary per group.
- Release run `33470204477`, job `99738282127`, used release-all and reported 6 hits / 15 misses. Six legacy Half-Life singleton groups were exact hits; seven overlapping groups expanded from one to four binaries; eight groups had not been requested by the earlier plan. The 15 misses covered 44 binaries and about 23m43s of reported warm time.
- Both source commits had the same root Git tree, both used bin commit `43a1cd9500f137007db7ce7abb9bafebc2e518fb`, and both used IDA 9.3. This rules out source, binary, and IDA-version drift for that incident.

### Optimization boundary

The current behavior is correct for the implemented immutable group identity but may duplicate work across scopes. Improving reuse requires an explicit design change: either publish one independent generation per binary, or make bound-plan warm the complete release group whenever it selects any module/platform member. The former improves composability but expands selection/locking/restore contracts; the latter preserves existing contracts but deliberately warms binaries outside the immediate PR plan. See [[Release bundle publication and recovery]] for the release consumer boundary.

## Failure and recovery
A version mismatch, active startup lock, memory admission failure, worker timeout/failure, invalid database set, or partial cleanup publishes nothing for that group. Pending/running siblings finish; successful sibling databases remain available for retry. A started worker is killed and waited before only its own complete database set, including stale `.id0`, may be invalidated. Cleanup residue is appended to the original failure instead of replacing it.

A corrupt generation is never repaired in place. Probe may rebuild a damaged READY pointer only from a fully verified immutable generation. Hard producer termination relies on the aggregate Job to reap descendants when enabled, but does not claim that workspace database cleanup completed.
## Verification
Repository tests cover kernel-only/current and seven-field/legacy identity validation, cache-key separation, canonical worker contract binding, exact generation publication/restore/prune, per-binary concurrency limits, `auto_wait()` false/exception behavior, worker exit and file-set checks, failure isolation, timeout kill/wait ordering, stale `.id0` invalidation, Windows sharing-violation retry, producer/tag lock scopes, LockFileEx interoperability with the former `msvcrt` byte range, finite memory admission, and process-level controller reuse.

A local real-IDA 9.3 smoke validated one generated `client.dll.i64`; a two-binary run measured 49.234s serial versus 24.640s at concurrency 2 (2.00x), with every worker and database-set validation succeeding. Production real-runner acceptance remains separate: inject a worker failure and timeout, exercise aggregate Job memory across two miss groups in an isolated producer process, and prove on distinct SMB3 runners that consumer restore overlaps workspace warm while publish/prune remains mutually exclusive with exact restore.