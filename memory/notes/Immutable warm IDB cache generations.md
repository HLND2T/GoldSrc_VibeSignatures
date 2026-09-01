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

- Bind binary path/size/SHA-256, IDA kernel/processor/bitness/file type, loader module digest, allowlisted plugin digests, normalized IDA arguments, and warm-worker source contract.
- Publish immutable generations through verified `.incoming-*` directories and atomic rename.
- Record the complete allowed `.i64`/`.idb` primary and side-file inventory; never publish active lock files.
- Restore only an exact generation selected by cache key and manifest SHA-256.
- Retain READY plus the newest three generations, with minimum-age protection for other generations.

## Architecture

`ida_database_paths.py` is the shared primary/side/lock path contract. `idb_cache.py` owns schema-1 identity, key, manifest, READY, publish, probe, verify, restore, and prune behavior. `idb_cache_locks.py` owns the cross-process tag lock and the fixed MCP-port lock; `idb_cache_selection.py` owns the canonical entry shape, coverage/identity validation, SHA-256 evidence files, the locked probe/warm/publish path, and the locked exact restore. `ida_runtime_probe.py` dynamically reads `idaapi.get_kernel_version()` through the runner Python installation and rejects an `idalib-mcp` executable outside that Python directory or its `Scripts` directory. `idb_cache.py` derives and holds the runner-local MCP port lock before launching the bounded `idb_warm_worker.py` subprocess, which observes runtime identity through the opened IDA session and saves a neutral database without dispatching project finder/Agent logic.

`write_canonical_json()` writes a UUID-named temporary file and retries Windows WinError 5/32 with bounded jitter before `os.replace`, treating an already-matching target as success. `READY.json` is only a discovery hint and its writes are idempotent. Once selected, a consumer carries exact `generation + cache_key + manifest_sha256`; later READY changes cannot redirect that run.

## Strict consumer

`IdaMcpLifecycle(database_policy="restored_strict", save_on_success=False)` requires an existing restored database. Identity mismatch fails without invalidation or cold rebuild. Successful selected-node changes are not saved back, so the immutable generation remains neutral.

## Workflow integration

The schema-2 trusted PR plan carries the invariant evidence field `cache_mode=warm`; it is not a user-selectable or repository-configurable mode. Every official analysis route splits producer from consumer through the reusable `warmup-idb.yml` job. The producer checks out the exact source in its own workspace, probes or warms under per-tag and MCP-port locks, and uploads canonical `cache-selection.json` plus its SHA-256. The consumer downloads that exact selection, verifies it against its own checkout and pinned runtime, restores the exact generations under the tag lock, and runs strict no-save analysis. The release build uses the same producer (`scope: release-all`) and a structurally identical consumer. Every official producer shares one repository-wide concurrency group (`idb-warmup-${{ github.repository }}`, `cancel-in-progress: false`). Verify/restore never re-read READY. A failed, cancelled, or skipped producer blocks analysis; there is no cold or consumer-side rebuild fallback. Release-all may materialize the binary-only accepted cache under `accepted-bin/locks/<gamever>.lock`; analysis YAML is excluded and artifact content intentionally does not participate in IDB cache identity.

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

A warm timeout, worker failure, observed-runtime mismatch, active lock, or partial database removes the current incomplete workspace database and publishes nothing. A corrupt generation is never repaired in place. Probe may rebuild a damaged READY pointer only from a fully verified immutable generation.

## Verification

Tests cover key sensitivity, PE32/ELF32 loader identity, both primary suffixes and side files, active locks (including a real cross-process probe), atomic JSON replacement retry/cleanup, idempotence, exact-selection restore after READY changes, release selection source/bin binding, manifest/binary/DB tampering, symlink/reparse rejection, retention, timeout/runtime mismatch cleanup, and strict lifecycle no-rebuild/no-save behavior.
