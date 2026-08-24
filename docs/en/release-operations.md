# Release operations

Phase 2 production authority is off unless both the dispatch requests activation and the repository variable
`GSVIBE_RELEASE_PHASE2_ENABLED` is `true`. Do not enable it until branch/ruleset, merge-commit-only and up-to-date policy,
protected tags, the `release` Environment, GitHub App identity/permissions, and the dedicated `gsvibe-release` runner have
captured protected-repository evidence.

`republish` additionally requires `GSVIBE_RELEASE_REPUBLISH_ENABLED=true`; keep that independent gate off until the
missing/corrupt asset exercise has completed in the protected test repository.

## State and truth sources

The private chain is `BUILDING -> HEAD_BOUND -> PR_CREATED -> READY -> PROMOTION_STARTED -> PROMOTED ->
PROMOTION_COMPLETE`. Every marker is immutable canonical JSON, hashes its predecessor, and retains non-null bindings.
Only the durable completion record plus the annotated tag identity, Release ID, and downloaded asset inventory means the
release is complete. Actions artifacts, a draft Release, `READY`, or `PROMOTED` alone are not completion.

## Protected operations

Run `release-operations.yml` with the exact tag/build and the requested confirmation:

- `retry`: allowed only before `PROMOTION_STARTED`; close the recorded PR, remove its immutable output branch, record
  `SUPERSEDED`, and dispatch a new build ID with the same content identity.
- `resume-promotion`: use the same build, PR head, merge commit, tag target, and original promotion workflow identity.
  The workflow checks out that exact verifier revision and resumes idempotent tag/asset/completion boundaries.
- `republish`: available only from durable completion. It rebuilds original bytes from the recorded merge, replaces only
  missing/corrupt named assets, downloads them again, and never changes the tag or tracked manifest.
- `abandon`: pre-promotion only, with `abandon:<tag>:<build-id>` and a reason. Any recorded PR is remotely verified before
  it is closed.
- `repair-index`: rebuilds only private `pr-index`/`READY` after exact repository, branch, PR, head, base, tag, build, and
  content identity match. Confirmation is `repair-index:<pr-number>:<tag>:<build-id>`.
- `cleanup`: requires `cleanup:<tag>:<build-id>`, `PROMOTION_COMPLETE`, and matching durable completion. It atomically
  renames the stage to `cleanup-trash/<tag>/<build-id>` and moves the PR index with it; deletion is a separate operator
  retention action.
- `reconcile`: read-only comparison of local markers/completion with the Git tag and Release. It reports differences and
  never repairs them automatically.

Preserve failed stages, operation logs, workflow URL/run/attempt, source/bin/workflow SHAs, approval digest, PR/head/merge
identity, tag object/target, Release ID, and downloaded hashes. Republish stays disabled in production until its protected
test-repository exercise succeeds.
