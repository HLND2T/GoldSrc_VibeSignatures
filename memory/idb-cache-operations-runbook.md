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
