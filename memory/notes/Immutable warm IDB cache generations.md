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

`ida_database_paths.py` is the shared primary/side/lock path contract. `idb_cache.py` owns schema-1 identity, key, manifest, READY, publish, probe, verify, restore, and prune behavior. `idb_warm_worker.py` is a bounded subprocess that holds the runner-local MCP port lock, observes runtime identity through the opened IDA session, and saves a neutral database without dispatching project finder/Agent logic.

`READY.json` is only a discovery hint. Once selected, a consumer carries exact `generation + cache_key + manifest_sha256`; later READY changes cannot redirect that run.

## Strict consumer

`IdaMcpLifecycle(database_policy="restored_strict", save_on_success=False)` requires an existing restored database. Identity mismatch fails without invalidation or cold rebuild. Successful selected-node changes are not saved back, so the immutable generation remains neutral.

## Workflow integration

The schema-2 trusted PR plan binds `cache_mode=warm|cold`. `idb_cache_workflow.py` verifies the exact merge commit and bin gitlink, derives only the selected analysis binary pairs, probes or warms under per-tag and MCP-port locks, and writes canonical `cache-selection.json` plus its SHA-256. Warm verify/restore never re-read READY. Cold mode skips all persisted-root steps. The dedicated `gsvibe-ida` runner keeps clean, restore, strict analysis, and final clean in one protected job.

## Failure and recovery

A warm timeout, worker failure, observed-runtime mismatch, active lock, or partial database removes the current incomplete workspace database and publishes nothing. A corrupt generation is never repaired in place. Probe may rebuild a damaged READY pointer only from a fully verified immutable generation.

## Verification

Tests cover key sensitivity, PE32/ELF32 loader identity, both primary suffixes and side files, active locks, atomic publication, idempotence, exact-selection restore after READY changes, manifest/binary/DB tampering, symlink/reparse rejection, retention, timeout/runtime mismatch cleanup, and strict lifecycle no-rebuild/no-save behavior.
