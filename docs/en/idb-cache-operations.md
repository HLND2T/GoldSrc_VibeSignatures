[Back to CI/CD](ci-cd.md) | [中文](../zh-CN/idb-cache-operations.md)

# IDB cache operations

## Activation checklist

Keep `GSVIBE_IDB_CACHE_MODE=cold` until the dedicated `gsvibe-ida` Windows runner, protected `win64` Environment,
outside-checkout persisted root, ACL owner, atomic rename storage, `IDADIR`, and expected kernel version are verified.
The persisted root must not contain the checkout or be contained by it, and neither its path nor root may traverse a
link or reparse point.

Capture one explicit cold run, one warm miss that publishes a generation, and a later warm hit for the same plan and
binary/runtime identity. Record run URL/attempt, source and bin SHAs, plan and selection SHA-256, cache key, generation,
manifest hash, and wall times. Only then set `GSVIBE_IDB_CACHE_MODE=warm`.

## Normal operation

Warm preparation is bounded and single-concurrency. A miss may publish a new immutable generation; a hit verifies the
exact generation before selection. `cache-selection.json` is uploaded as evidence, not cache transport. The consumer
rechecks its SHA-256 and pinned runtime identity, restores exact entries without consulting READY, and runs strict
no-save analysis. Final workspace clean removes restored and modified databases without deleting generations.

Run `uv run python idb_cache.py prune -persisted-root <root> -tag <tag>` only under the same runner authority. Prune keeps
READY and the newest three valid generations, honors the minimum age, and only visits that tag. Retired tags require an
offline maintenance window: stop new IDA jobs, acquire the tag authority, move the exact tag directory to recoverable
operator trash, record its inventory and reason, then delete it only after the in-flight retention window expires.

## Failures

Do not repair a corrupt generation in place. Preserve the selection and logs, switch future plans explicitly to cold or
start a new warm producer run, and quarantine the corrupt generation after confirming no in-flight selection references
it. A strict consumer failure never falls back inline. A damaged READY pointer may be rebuilt only by probing verified
immutable generations.
