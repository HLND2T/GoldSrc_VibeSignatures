[Back to CI/CD](ci-cd.md) | [中文](../zh-CN/idb-cache-operations.md)

# IDB cache operations

## Activation checklist

Keep `GSVIBE_IDB_CACHE_MODE=cold` until the dedicated Windows runner, protected `win64` Environment,
outside-checkout persisted root, ACL owner, atomic rename storage, and `IDADIR` are verified. Confirm that `python` with
`idapro` and `idalib-mcp` resolve to the same installation; CI dynamically reads its kernel version. The persisted root
must not contain the checkout or be contained by it, and neither its path nor root may traverse a link or reparse point.

Splitting the producer into its own job additionally requires cross-runner evidence: every eligible runner resolves
`PERSISTED_WORKSPACE` to the same controlled storage, a generation published on runner A verifies on runner B, that
storage supports same-directory atomic rename, all runner accounts share one ACL authority, and Windows byte-range locks
are mutually exclusive across two independent processes on that storage. Until every item holds, keep
`GSVIBE_IDB_CACHE_MODE=cold`; merging the workflow YAML is not activation.

Capture, in order: one explicit cold run; one split-job warm miss that publishes generations; a later warm hit whose
consumer runs on a different runner; a run where READY advances between producer and consumer yet the exact restore
still succeeds; two release versions dispatched together where the second producer queues; a source PR and a release
requesting warmup together with still only one producer running; a cancelled/timed-out producer after which no
half-written generation is ever selected; a corrupt generation or selection failing closed; and a failed build whose
workspace cleanup leaves the persisted generations intact. Record run URL/attempt, runner identity, source and bin SHAs,
plan and selection SHA-256, cache key, generation, manifest hash, and wall times.

## Normal operation

Warm production runs in the reusable `warmup-idb` job. Every official producer — release and source PR alike — shares
the single job-level concurrency group `idb-warmup-<owner>/<repo>` with `cancel-in-progress: false`, so the scheduler
allows one persisted IDB cache writer per repository at a time. Within a producer, each tag's
`probe -> warm/publish -> verify -> selection -> prune` runs under
`<PERSISTED_WORKSPACE>/idb-cache/.locks/<tag>.lock`; consumers hold the same lock across `verify -> restore` so a
concurrent prune cannot delete a generation that was already selected. A lock is held by an open handle, never by the
lock file existing.

A miss publishes a new immutable generation; a hit verifies the exact generation before selection. Hit and miss produce
byte-identical selection entries. `cache-selection.json` is evidence and selection transport, not IDB payload transport.
The consumer rechecks its SHA-256 against the producer job output, re-derives the expected identities from its own
checkout and pinned runtime, restores exact entries without consulting READY, and runs strict no-save analysis. Final
workspace clean removes restored and modified databases without deleting generations.

Accepted-bin materialization for both producer and consumer goes through
`uv run python release_workflow.py materialize-accepted-bin --repo-root <checkout> --persisted-root <root> --all-gamevers`.
It holds `<PERSISTED_WORKSPACE>/release-staging/locks/<gamever>.lock` — the same key release promotion takes around its
directory swap — copies only durable files (IDA databases and BinSync state are excluded), and verifies the copied
inventory before releasing the lock. Do not hand-copy the accepted tree.

Run `uv run python idb_cache.py prune -persisted-root <root> -tag <tag>` only under the same runner authority. Every
mutating `idb_cache.py` subcommand (`probe`, `warm`, `publish`, `restore`, `prune`) acquires the tag lock itself, so a
direct CLI invocation cannot bypass the authority; only `verify` is lock-free because it is read-only. Prune keeps
READY and the newest three valid generations, honors the minimum age, and only visits that tag. Retired tags require an
offline maintenance window: stop new IDA jobs, acquire the tag authority, move the exact tag directory to recoverable
operator trash, record its inventory and reason, then delete it only after the in-flight retention window expires.

## Failures

Do not repair a corrupt generation in place. Preserve the selection and logs, switch future plans explicitly to cold or
start a new warm producer run, and quarantine the corrupt generation after confirming no in-flight selection references
it. A strict consumer failure never falls back inline. A damaged READY pointer may be rebuilt only by probing verified
immutable generations.

A failed producer, a cancelled producer, or a selection artifact that cannot be downloaded all block the consumer. That
is deliberate fail-closed behaviour bought by exact binding: recovery is a new run, never a consumer-side re-probe.
Report IDB cache restore success and full business analysis success separately — a healthy restore does not excuse a
later analysis or Skill failure.
