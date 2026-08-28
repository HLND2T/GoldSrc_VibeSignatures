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

The schema-2 trusted PR plan carries the invariant evidence field `cache_mode=warm`; it is not a user-selectable or repository-configurable mode. Every official analysis route splits producer from consumer through the reusable `warmup-idb.yml` job. The producer checks out the exact source in its own workspace, probes or warms under per-tag and MCP-port locks, and uploads canonical `cache-selection.json` plus its SHA-256. The consumer downloads that exact selection, verifies it against its own checkout and pinned runtime, restores the exact generations under the tag lock, and runs strict no-save analysis. The release build uses the same producer (`scope: release-all`) and a structurally identical consumer. Every official producer shares one repository-wide concurrency group (`idb-warmup-${{ github.repository }}`, `cancel-in-progress: false`). Verify/restore never re-read READY. A failed, cancelled, or skipped producer blocks analysis; there is no cold or consumer-side rebuild fallback. Accepted-bin materialization is a single helper holding the same per-gamever lock release promotion takes around its directory swap.

## Failure and recovery

A warm timeout, worker failure, observed-runtime mismatch, active lock, or partial database removes the current incomplete workspace database and publishes nothing. A corrupt generation is never repaired in place. Probe may rebuild a damaged READY pointer only from a fully verified immutable generation.

## Verification

Tests cover key sensitivity, PE32/ELF32 loader identity, both primary suffixes and side files, active locks (including a real cross-process probe), atomic JSON replacement retry/cleanup, idempotence, exact-selection restore after READY changes, release selection source/bin binding, manifest/binary/DB tampering, symlink/reparse rejection, retention, timeout/runtime mismatch cleanup, and strict lifecycle no-rebuild/no-save behavior.
