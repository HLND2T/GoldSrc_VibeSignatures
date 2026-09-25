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

Do not enable or dispatch official analysis until the dedicated Windows runner, protected `win64` Environment,
checkout-external persisted root, ACL owner, atomic-rename storage, and consumer `IDADIR` are verified. Governance of
those surfaces is in [[self-hosted-runner-and-governance]]. Merging workflow YAML is not activation. Official analysis
is always a strict warm consumer — there is no cold bypass and no consumer-side rebuild fallback.

Cross-runner evidence is additionally required when the producer is split into its own job:

- every eligible runner resolves `PERSISTED_WORKSPACE` to the same controlled storage;
- a generation published on runner A verifies on runner B;
- storage supports same-directory atomic rename;
- all runner accounts share one ACL authority;
- Windows byte-range locks are mutually exclusive across two independent processes on that storage.

Capture evidence in order: one split-job warm miss that publishes; a later warm hit whose consumer runs on a different
runner; a run where READY advances between producer and consumer yet the exact restore still succeeds; two release
versions dispatched together where the second producer queues; a source PR and a release requesting warmup together with
still only one producer running; a two-worker miss faster than the serial baseline; a worker failure/timeout reaped
before only its own database files (plus stale `.id0`) are removed while siblings finish; memory-budget rejection and
finite admission timeout; a corrupt generation or selection failing closed; and a failed build whose workspace cleanup
leaves persisted generations intact. Record run URL/attempt, runner identity, source and bin SHAs, plan and selection
SHA-256, cache key, generation, manifest hash, worker counts, and wall times.

## Normal operation

Warm production runs in the reusable `warmup-idb` job; official and direct producers share the job-level concurrency
group (`idb-warmup-<owner>/<repo>`, `cancel-in-progress: false`) plus the persisted `producer.lock`. A miss is probed
under a short tag lock, warmed outside that lock by one bare-idalib process per binary, then re-probed/published/
verified/pruned after reacquiring the tag lock. Consumers hold only the tag lock across `verify -> restore`, so they can
restore while another producer warms but cannot race its publish/prune. A lock is held by an open handle, never by the
lock file existing. Hit/miss selection semantics, `cache-selection.json` transport role, and strict no-save consumer
analysis are documented in [[Immutable warm IDB cache generations]].

## Prepare performance

PR and release selection producers first probe/verify/prune different tags in a bounded thread pool. The limit reuses
`--max-concurrency` / `IDB_WARMUP_MAX_CONCURRENCY` (default `2`, `1` for serial probes); platforms within one tag retain
input order and share the existing tag lock. After every probe task finishes successfully, miss groups warm and publish
one group at a time, retaining per-binary worker concurrency and the single process memory owner. A probe-task failure
waits for the pool to finish and aborts preparation before warming or writing a selection.

Each Prepare creates a unique schema-2 selection lease owned by repository/run/attempt. Verified hits and miss
publications are pinned under their tag lock before pruning or releasing the lock. Preparing pins protect early entries
while other groups warm; after all entries exist, every tag's lease is sealed to the canonical selection SHA-256 before
any selection/evidence files are written. Persistent protection covers other producers and the downstream job queue.
It does not bypass manifest/payload validation or ordinary retention for unleased generations.

The lease lasts 36 days from creation (the 35-day GitHub whole-workflow limit plus one day), and pruning adds one hour
of clock-skew grace. The consumer rejects expired, missing, unsealed, or mismatched leases before copying. All entries
must restore successfully before any of this selection's pins are released; partial failure keeps all pins. Independent
verify never releases or renews pins. A cancelled producer, failed artifact upload, or killed consumer leaves pins for
bounded expiry reclamation. Prune validates the complete lease inventory before any deletion; malformed, unreadable,
unknown-version, or reparse-point metadata aborts pruning for that tag. Logs include pin/seal/release/expiry and every
pruned generation and reason.

Payloads, READY, and leases now live under `PERSISTED_WORKSPACE/idb-cache-v2/<tag>/`. The old
`idb-cache/.locks/` remains the shared producer/tag coordination namespace so old and new producers cannot warm
concurrently. Old source revisions only prune their original payload directory and cannot delete v2 pins or generations.
Initial v2 use rebuilds the cache; there is no automatic import or deletion of legacy payloads. Do not move or delete
the old `.locks` directory during legacy-data maintenance.

A successful full restore consumes its selection's lease. Retrying only a later failed consumer job is not guaranteed
once that lease is released or expired: re-run the full workflow including its producer for a new selection and lease.
Generation names identify historical creators; lease ownership identifies the current consumer's producer, including
cache hits and different attempts. Archived release evidence accepts legacy schema 1 and leased schema 2 descriptors
without consulting live pins, so releases remain verifiable after restore or expiry.

Both READY and fallback hits still hash the complete generation inside the probe's tag lock; only the immediate second hit
verification is removed. Prune also hashes historical generations, and final selection validation before and after writing
still performs full verification. Entries remain canonically sorted regardless of thread completion order.

Flushed `prepare_*` stage logs separate binding/binary identities, parallel probe wall time, per-group probe/verify, prune,
warm, publish/re-probe/verification, selection validation, and writing. Lock acquisition logs report wait time. Per-group
hit/miss durations exclude time queued behind other groups, so concurrent durations must not be summed as total wall time.
Compare repeated runs on the same runner with the same selection and comparable cold/warm storage state; record manifest
`files[].size` totals per group and distinguish prune's historical payload reads from the selected payload. Disk
throughput determines the benefit — local unit tests do not establish production speedup.

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
`--worker-timeout-seconds` to worker execution only. Prune keeps READY plus the newest three valid generations, honors
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
- Scope: shared PR/release IDB cache handoff. IDB identity, manifest, neutral payloads, and strict no-rebuild analysis remain intact. Archived release evidence validates schema 1 or schema 2 descriptors independently of live lease state or today's retention policy.

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