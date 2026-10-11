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
- Bind each binary's module/platform/path/size/SHA-256, tag, IDA kernel version, empty compatibility-only `normalized_ida_args`, and canonical three-file warm-worker source contract.
- Warm only cache misses, using one bare-idalib process per binary and bounded concurrency within each tag/platform batch.
- Publish one immutable generation per binary through verified `.incoming-*` directories and atomic rename.
- Record the complete allowed `.i64`/`.idb` primary and side-file inventory; never publish active lock files.
- Restore only exact generations selected by cache key and manifest SHA-256; consumers never re-probe or rebuild.
- Retain READY, live leased generations, and the newest three valid generations per binary target, with minimum-age protection.
- Store payloads/READY/schema-2 lease records in `idb-cache-v3/<tag>/`. Shared producer/tag locks remain in `idb-cache/.locks/`.
- Bind schema-3 PR/release selections to unique repository/run/attempt leases. Pin each verified binary before unlocking; seal each tag's pin to the complete canonical selection digest before publishing evidence.
- Release this selection's pins only after every entry restores successfully; read-only verify and partial failure retain all pins.
- Reclaim abandoned pins after 36 days plus one hour of pruning clock grace. Malformed/unreadable metadata blocks pruning.
- Keep historical release selection schema 1/2 readable offline; the active producer/consumer protocol requires schema 3.
## Involved Files & Symbols

- `idb_warm_worker.py` — `ida_kernel_version()`, `warm_binary()`
- `idb_cache.py` — `warm_group()`, `_run_one_worker()`, `publish_generation()`
- `ida_database_paths.py` — `database_cleanup_paths()`
- `idb_cache_locks.py` — `producer_lock()`, `tag_lock()`, `exclusive_file_lock()`
- `idb_cache_selection.py` — `prepare_selection_entries()`, `seal_selection_leases()`, `restore_selection_entries()`
- `idb_cache_leases.py` — atomically persisted preparing/sealed pins, exact owner/digest/reference binding, bounded reclamation
- `warmup_memory.py` — `ProducerMemoryOwner`, `MemoryLaunchGate`, `WindowsJobMemoryController`
- `idb_cache_release.py` / `idb_cache_workflow.py` — release-all and bound-plan producers/consumers
- `.github/workflows/warmup-idb.yml` — canonical IDA Python binding and producer configuration

## Architecture
`ida_database_paths.py` owns primary/side/lock paths and failure cleanup. `idb_warm_worker.py` opens one binary through bare idalib, waits for auto-analysis, saves and closes its neutral database. `auto_wait()` false fails without saving.

`idb_cache.py` retains schema-1 identity/manifest validation, verified immutable publication, READY probe hints and exact restore. Official generations contain one binary. `warm_group()` remains a bounded worker batch and requires every admitted worker to finish successfully before its caller publishes any member. Pruning retains history independently by module/platform/path, including changed bytes or runtimes of the same target.

`idb_cache_selection.py` projects the PR/release tag/platform warming batches onto singleton identities. Tags probe in a bounded thread pool; verified hits are pinned under their tag lock. After the probe barrier, only missing binaries warm in serial tag/platform batches with bounded worker concurrency. Each miss is re-probed, independently published/verified and pinned under its tag lock. Each tag is pruned once after all selected members are pinned. Selection entries sort by tag/platform/module/path; lease references sort uniquely by platform/cache key.

`idb_cache_locks.py` keeps the shared repository producer lock and short tag locks. Consumers hold the tag lock across exact verify/restore, and release all pins only after the complete selection copies successfully. New payloads live in `idb-cache-v3`, so older source revisions cannot prune them. First use warms the new namespace; prior group caches are not imported.

`warmup_memory.py` retains one process-level memory owner, a fresh baseline/launch gate per missing platform batch, and the existing finite admission/worker failure authority.
## Strict consumer

`IdaMcpLifecycle(database_policy="restored_strict", save_on_success=False)` requires an existing restored database. Identity mismatch fails without invalidation or cold rebuild. Successful selected-node changes are not saved back, so the immutable generation remains neutral.

## Workflow integration
S3 transport uses `idb_cache_s3.py`: each immutable singleton generation becomes one gzip tar object in the separate `gsvibe-idb-objects-v1/<repository-sha256>/` namespace. Producers prefetch only requested cache identities using small mutable discovery references, then upload only absent objects. The existing schema-3 selection remains the workflow manifest. An immutable receipt keyed by its SHA-256 carries the producer's original sealed lease records and is published after all objects; consumers verify the caller-bound selection digest and receipt, download exact generations without probing references, and retain existing full identity/payload/lease checks. SDK conditional writes and post-publication metadata checks protect immutable objects; streamed extraction validates the complete allowed file inventory before atomic installation. No remote GC or legacy snapshot import is performed. Generation age alone cannot govern remote retention because future selections can reuse old objects under fresh leases.

Issue #360 verification: new transport tests first failed before implementation. Deterministic coverage includes subset-only transfer, warm-hit upload reuse, independent miss warming, exact restore despite changed discovery hints, missing/corrupt objects, archive path/link/duplicate/inventory rejection, lease/digest binding, publication failure, conditional writes, multipart abort and concurrent-write conflicts. The real Boto3 request model is exercised with Stubber. The complete Windows suite ran 1504 tests in 220.017 seconds with zero failures and 16 platform/service/opt-in skips; repository formatting, new transport/runner Ruff checks, actionlint (without ShellCheck) and diff whitespace checks passed. No real S3 or GitHub runner acceptance was run: S3 endpoint/access-key/secret-key environment variables were unavailable. Endpoint conditional-write compatibility and cold/warm transfer measurements remain rollout verification.

The schema-2 trusted PR plan carries the invariant evidence field `cache_mode=warm`; it is not user-selectable. Every official analysis route uses the reusable `warmup-idb.yml` producer. The workflow canonicalizes one PATH-resolved IDA Python executable, obtains its kernel version through `idb_warm_worker.py --print-ida-version`, and passes that executable to release-all or bound-plan preparation. The producer no longer requires `idalib-mcp` or `IDADIR`; strict consumers still use [[idalib-mcp]] for analysis.

A `source_artifact_mode=tracked` release is not an analysis route: it schedules no `warmup-idb` producer, downloads or restores no selection, and never opens an IDB, so its manifest carries no warm IDB selection digest.

Official producers share the repository-wide Actions concurrency group (`idb-warmup-${{ github.repository }}`, `cancel-in-progress: false`). Official and direct producers also share persisted `idb-cache/.locks/producer.lock`, so a bypass invocation cannot overlap the official producer. Verify/restore never re-read READY. A failed, cancelled, or skipped producer blocks analysis; there is no cold or consumer-side rebuild fallback.

## Bound-plan consumer validation cost

- **Trigger signal:** Adjacent PR Verify/Restore steps take similar time while the logged restore loop is much shorter.
- **Root cause / constraints:** `restore_cache_selection()` already performs full verification. Artifact binding validates the complete tag inventory, and per-file Git probes plus reads incur two process launches per blob. Buffered log timestamps do not measure the restore loop; use its monotonic durations.
- **Correct approach:** The PR workflow checks downloaded selection evidence against the producer job output, then invokes `restore` once. Standalone `verify` remains available. `GitRepository.read_many()` uses one binary `cat-file --batch` exchange per nonempty tag inventory, with the tree and blobs pinned to the same commit. Config verification reuses one read. Required/optional path rules, original bytes, size/SHA-256 and canonical inventory digest remain unchanged.
- **Verification:** Real-Git tests cover binary bytes, missing/non-blob objects, symbolic-ref movement and one batch per inventory; malformed protocol responses fail closed. Direct restore rejects evidence, plan, binary/runtime and payload mismatches before copying. Flushed stage timings distinguish checkout/plan binding, bound inputs/binary identities, selection/payload validation and locked exact restore. Production performance requires comparable repeated runner measurements, separate from local reader microbenchmarks.
- **Scope:** No plan/cache schema, READY selection, per-tag locking or completeness-proof change. Restore retains full verification and locked exact generation checks; no skip-verification token or cold fallback is introduced.

## Concurrent bare-idalib warmup

- **Trigger signal:** A cache-miss group contains several binaries and wall time scales as their serial sum, or a fixed MCP port lock prevents overlapping workers.
- **Root cause / constraints:** idalib owns one open database per process. MCP-port serialization is unnecessary for neutral warming, but immutable group publication, exact selection, producer/tag lock authority, worker ownership, and stale `.id0` safety must remain fail-closed.
- **Correct approach:** Run one canonical bare-idalib worker per binary, bound to the same probed IDA Python executable. Bound concurrency with `IDB_WARMUP_MAX_CONCURRENCY` (default 2). When `IDB_WARMUP_MAX_MEMORY_MIB` is configured, admit through a finite per-task deadline on a reused process-level controller; otherwise retain each worker's own memory limit. The controller's tier decides the per-worker flag: an aggregate hard cap (Windows Job, Linux cgroup v2) disables the per-worker limit to avoid double counting, while the `reservation-only` tier keeps it and adds a resident-memory watchdog at the reservation.
- **Failure authority:** Admission, preflight, and spawn failures do not grant failed-worker cleanup authority. After an actual worker starts, only its producer owner may invalidate `database_cleanup_paths()` and only after confirmed process exit. Startup `.id0` remains an active-lock signal. Windows WinError 5/32 deletion retries are bounded.
- **Verification:** Unit tests cover `auto_wait=False`, explicit IDA executable binding, max concurrency, sibling isolation, timeout kill/wait-before-cleanup, stale lock cleanup, transient delete retry, producer/tag lock boundaries, legacy identity reads, and controller reuse. Production activation additionally requires real Windows Job, throughput, and cross-runner SMB3 evidence.
- **Scope:** Worker lifecycle and memory/concurrency controls remain shared by warming batches. Independent binary publication is described below; strict consumer policy and exact restore still apply.

## Cache group granularity and cross-scope reuse
PR and release producers now publish one generation per binary, using schema-3 selection entries with singleton `binaries[]`. `per_binary_identities()` projects the existing tag/platform batches before probing, so adding/removing another module does not change this binary's cache key. PR subsets and release-all reuse the same singleton generations when tag, module/platform/path, binary bytes, runtime and worker contract agree.

A changed or corrupt binary is rebuilt independently while healthy siblings remain hits. Cold misses on the same platform still warm together, preserving worker concurrency and the single memory owner. Leases protect several distinct cache keys on one platform; prune retains three generations per binary target and runs once per tag after all pins exist.

- Trigger: neighboring PRs request different module sets but the selected binary records are unchanged.
- Previous root cause: the old key bound the whole module set; a four-module generation could not satisfy a three-module selection.
- Current approach: independent singleton keys/generations, exact per-binary coverage and lease references, isolated v3 payloads, no old-group migration.
- Verification: deterministic tests cover cold batches with independent publication, subset/expansion hits, rebuilding only changed/corrupt binaries, partial restore pins, per-target retention and old namespace isolation. Real runner speedup remains unmeasured.
- Scope: PR and release preparation/restore plus release evidence validation. Historical selection schemas 1/2 remain readable offline; active workflows require schema 3.

Historical examples: on 2026-09-01 a singleton PR cache preceded a release requesting four-member groups and produced 15 misses covering 44 binaries. On 2026-10-02 run `36966414604` selected `engine + gameui + serverbrowser` where the earlier run had also selected `vgui2`; all 15 overlapping groups missed despite unchanged selected binary records. These describe the retired group cache behavior.

See [[idb-cache-operations-runbook]] for first-use and lease recovery procedures and [[Release bundle publication and recovery]] for archived evidence.
### Diagnostic signature
These diagnostics apply to the retired combination cache only: changes to the selected module set changed the whole group's key even when its binary bytes were unchanged. The active schema-3 protocol probes each binary independently; its hit/miss log identifies module and path. Changes to another member no longer invalidate the selected binary.
### Activation boundary
The active v3 namespace is warmed on first use. It does not import old combination generations. Exact restore, binary/runtime/worker binding, live leases and immutable payload checks remain required. Historical release evidence uses its recorded schema and is verified offline without live pins; it is not an active cache selection.
## Failure and recovery
A version mismatch, active startup lock, memory admission failure, worker timeout/failure, invalid database set, or partial cleanup publishes nothing for that group. Pending/running siblings finish; successful sibling databases remain available for retry. A started worker is killed and waited before only its own complete database set, including stale `.id0`, may be invalidated. Cleanup residue is appended to the original failure instead of replacing it.

A corrupt generation is never repaired in place. Probe may rebuild a damaged READY pointer only from a fully verified immutable generation. Hard producer termination relies on the aggregate Job to reap descendants when enabled, but does not claim that workspace database cleanup completed.
## Verification
Repository tests cover kernel-only/current and seven-field/legacy identity validation, cache-key separation, canonical worker contract binding, exact generation publication/restore/prune, per-binary concurrency limits, `auto_wait()` false/exception behavior, worker exit and file-set checks, failure isolation, timeout kill/wait ordering, stale `.id0` invalidation, Windows sharing-violation retry, producer/tag lock scopes, LockFileEx interoperability with the former `msvcrt` byte range, finite memory admission, and process-level controller reuse.

A local real-IDA 9.3 smoke validated one generated `client.dll.i64`; a two-binary run measured 49.234s serial versus 24.640s at concurrency 2 (2.00x), with every worker and database-set validation succeeding. Production real-runner acceptance remains separate: inject a worker failure and timeout, exercise aggregate memory admission across two miss groups in an isolated producer process, and prove on distinct SMB3 runners that consumer restore overlaps workspace warm while publish/prune remains mutually exclusive with exact restore.

## Per-binary implementation verification (2026-10-02)

- TDD: seven deterministic per-binary regressions failed against the group cache and passed after the change; archive schema-3 coverage received a separate regression.
- Related cache/lease/release/warmup tests: 114 passed.
- Required `uv run python tests/run_test_suite.py all -b --durations 30`: 1389 tests, exit 0, nine skips (three POSIX-only tests, two opt-in notes CLI tests, three Redis integration classes because no Redis service was available, and opt-in real IDA integration).
- `uv run python format_repo_files.py --check`: exit 0; 648 Python and 29 YAML files checked. Independent read-only invariant review found no concrete regression.
- These results establish local behavior/contract coverage. This change has no real-runner cold/warm wall-time measurement or cross-runner storage acceptance yet.
