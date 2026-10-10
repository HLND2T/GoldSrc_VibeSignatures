---
title: idb-cache-operations-runbook
type: note
permalink: goldsrc-vibesignatures/idb-cache-operations-runbook
tags:
- idb-cache
- runbook
- operations
- self-hosted
- warmup
---

# IDB cache operations runbook

Operator-facing procedures for the warm IDB cache. Architecture, schema-1 identity, lock scopes, READY semantics,
selection/restore internals, and worker failure authority live in [[Immutable warm IDB cache generations]] and are not
repeated here — this note organizes the operational checklist, normal-operation flow, maintenance commands, and
operator failure semantics.

## Activation checklist (do not dispatch official workflows until verified)
Before official analysis, verify a prepared Windows x64 or Ubuntu x64 runner with `cross-platform`, protected `win64` Environment, private S3 access, exact binary submodule access, native licensed IDA/idalib, paired host Python and `idalib-mcp`, and consumer `IDADIR`. Merging YAML does not activate a runner. Official analysis remains a strict warm consumer with no rebuild fallback.

Cross-runner transport uses immutable S3 snapshots and separate local staging roots, not shared `PERSISTED_WORKSPACE` storage. Verify local atomic rename/process locks and runner account ownership; validate the exact generation/manifest, selection digest and live sealed lease after transport. Discovery uses repository-wide shared, then legacy Windows/Linux/macOS prefixes. Consumers may not use discovery fallbacks.

Record real CI evidence: cold warm miss and publication, repeat warm hit, Windows producer → Linux consumer, READY advancing while exact restore succeeds, queued concurrent producers, failed/cancelled MCP workers fully reclaimed, corrupted generation/selection rejected, and PR analysis plus non-publishing Release in both `rebuild` and `tracked` modes. Capture run URL/attempt, runner OS/identity, source/bin SHAs, selection digest, exact key, generations, manifests and timings. Synthetic/local tests do not prove commercial IDA execution, S3 publication or GitHub runner readiness; issue #356 remains open until this evidence exists.

## Normal operation

Warm production runs in the reusable `warmup-idb` job; official and direct producers share the job-level concurrency
group (`idb-warmup-<owner>/<repo>`, `cancel-in-progress: false`) plus the persisted `producer.lock`. A miss is probed
under a short tag lock, warmed outside that lock by one bare-idalib process per binary, then re-probed/published/
verified after reacquiring the tag lock; pruning runs once per tag after all selected binaries are pinned. Consumers hold only the tag lock across `verify -> restore`, so they can
restore while another producer warms but cannot race its publish/prune. A lock is held by an open handle, never by the
lock file existing. Hit/miss selection semantics, `cache-selection.json` transport role, and strict no-save consumer
analysis are documented in [[Immutable warm IDB cache generations]].

## Prepare performance
PR and release producers probe individual binaries across tags in a bounded thread pool. The pool limit reuses `--max-concurrency` / `IDB_WARMUP_MAX_CONCURRENCY` (default `2`); platform batches within a tag keep input order and share its existing lock. A failed probe waits for the pool and aborts before warming or writing a selection.

After the probe barrier, only missing binaries warm together within their tag/platform batch. Batches run serially using the single process memory owner, while each batch retains bounded per-binary worker concurrency. Each successful member is independently re-probed/published/verified and pinned. Prune runs once per tag after all selected hits and misses have pins, retaining READY, live pins, minimum-age protection and three valid generations per binary target.

Each Prepare creates a schema-3 selection with one singleton entry per binary and a unique repository/run/attempt lease. Its on-disk schema-2 lease record supports several cache keys on one platform; references are uniquely sorted by platform/cache key. All tag pins are sealed to the canonical selection SHA-256 before selection/evidence files are written.

Leases last 36 days, with an extra one-hour pruning clock allowance. All entries must restore successfully before any pins are released. Partial failure, producer cancellation or failed artifact upload retains pins for bounded expiry reclamation. Malformed, unreadable, unknown-version or linked lease metadata blocks pruning before any deletion.

Official CI payloads, READY and leases live in disposable `IDB_CACHE_ROOT/idb-cache-v3/<tag>/` restored from S3. Direct local maintenance still accepts an explicitly governed persisted root. Existing `idb-cache/.locks/` coordinates all source revisions. New workflows use only the v3 payload namespace: first use warms each requested binary once, without importing prior combination caches. Older revisions can continue using their own payload directories and cannot prune v3 generations. Never move/delete the shared lock directory during maintenance.

A full restore consumes its lease. Re-run the entire workflow, including the producer, after a missing/released/expired pin; retrying only a consumer does not guarantee availability. Active consumers require selection schema 3. Archived release evidence accepts schemas 1/2/3 without live storage or pin lookups.

READY/fallback probes, historical prune, final selection validation and exact restore retain full payload verification. Entries sort by tag/platform/module/path. Logs identify each binary, separate parallel probe wall time, missing-batch warm time, per-binary publication, per-tag prune and final validation. Miss-entry durations include shared batch warm time and must not be summed as total wall time. Real storage/runner measurements are needed to establish production speedup.
## Accepted-bin and legacy-YAML maintenance

Run these only under the same runner authority (full contract in [[Release bundle publication and recovery]]):

- `materialize-accepted-bin --repo-root <checkout> --persisted-root <root> --all-gamevers` copies only binary/side
  files under `accepted-bin/locks/<gamever>.lock` and verifies every copied byte before releasing the lock.
- `cleanup-legacy-accepted-yaml --cutover-id <id>` first verifies binary-only materialization, then creates an exact
  inventoried backup under `accepted-bin/legacy-yaml-backups/` before deleting the locked YAML inventory. Rerun after an
  interrupted rename or partial deletion; it resumes only from the canonical matching backup.
- Never hand-copy or hand-delete the accepted tree.

## Prune and retired-tag maintenance

`prune -persisted-root <root> -tag <tag>` runs only under the same runner authority. Direct `warm`, `publish`, and
`prune` acquire the producer lock plus the relevant short tag lock; `restore` and `probe` acquire the tag lock; read-only
`verify` is lock-free. Direct `warm` requires `--ida-python`, accepts `--max-concurrency`, and applies
`--worker-timeout-seconds` to worker execution only. Prune keeps READY plus the newest three valid generations per binary target, honors
the minimum age, and visits only that tag.

Retired tags require an offline maintenance window: stop new IDA jobs, acquire the tag authority, move the exact tag
directory to recoverable operator trash, record its inventory and reason, then delete it only after the in-flight
retention window expires.

## Operator failure semantics

- Corrupt generations are never repaired in place: preserve the selection and logs, start a new warm producer run, and
  quarantine the corrupt generation only after confirming no in-flight selection references it.
- A strict consumer failure never falls back inline; a damaged READY pointer is rebuilt only by probing verified
  immutable generations (internals in [[Immutable warm IDB cache generations]]).
- A failed or cancelled producer, or an undownloadable selection artifact, all block the consumer — deliberate
  fail-closed behaviour. Recovery is a new run, never a consumer-side re-probe.
- Report IDB cache restore success and full business analysis success separately: a healthy restore does not excuse a
  later analysis or Skill failure.
- Worker failure never publishes a partial group: pending/running siblings finish, and cleanup retries only Windows
  sharing violations while reporting residual paths without replacing the original worker error.

## Validation

Coverage for these procedures is exercised by the warm-cache test surface plus the real-runner acceptance described in
[[Immutable warm IDB cache generations]] and the release runner evidence gates in [[self-hosted-runner-and-governance]].

## Issue #239: cross-job selection lifetime and recovery

- Trigger: an old cache hit verifies during Prepare, then another run selects a different identity and prunes before the first consumer starts; restore reports `Generation is not a plain directory`.
- Root cause: producer serialization and tag locks protect operations, while the old in-memory protected set ended with one Prepare. Neither protected the handoff/queue between jobs.
- Correct approach: persist and seal pins before publishing exact selections, consult all pins before pruning, release only after complete restore, and isolate v2 payloads from old source revisions' pruning.
- Verification: the deterministic A-Prepare/B-Prepare/A-restore regression failed before the fix; local tests cover cross-process prune/restore into another workspace, hit/miss pins, multi-platform and multi-tag partial failure, independent owners/attempts, expiry/clock grace, malformed metadata, symlinks, publication failure, and legacy namespace isolation. Real Windows/SMB multi-runner acceptance remains a separate rollout gate; Linux process-lock tests do not establish SMB behavior.
- Scope: shared PR/release IDB cache handoff. IDB identity, manifest, neutral payloads, and strict no-rebuild analysis remain intact. Archived release evidence validates selection schemas 1, 2 and 3 independently of live lease state or today's retention policy.

Corrupt lease recovery is deliberately manual: stop new work for the affected tag, identify and drain/cancel all possibly
referencing producer/consumer runs, preserve the exact lease bytes and generation inventory for diagnosis, then under
the existing tag lock quarantine the damaged metadata outside `leases/`. Do not remove a pin merely because its JSON
cannot be parsed; its owner cannot be determined safely. Resume with a full workflow including warmup. Future-dated
pins beyond the one-hour clock allowance also block pruning: correct runner clocks and establish owner status first.
The original `idb-cache/.locks/` remains live coordination data and is never retired with legacy payloads.

## Cross-platform lease failure-injection paths

- Trigger: Windows CI reports `IdbCacheError not raised` in the unreadable-lease test while Linux passes.
- Root cause/constraint: the fixture retains the temporary path spelling while `_tag_root()` resolves it. Lexical `Path` equality does not identify the same file across equivalent spellings, including Windows short/long names; the permission-error injector can silently miss its target.
- Correct approach: match the existing target with `Path.samefile()` when injecting a file-specific read failure. Exercise a noncanonical `persisted/../persisted` root on all platforms so the regression does not depend on Windows being available.
- Verification: adding that alias reproduces the CI assertion on Linux before the matcher fix; after the fix all 15 lease tests pass, retaining assertions that unreadable metadata raises and prevents deletion.
- Scope: test fault injection only; production lease validation and pruning are unchanged. The new Windows CI run must confirm the original platform failure is resolved.