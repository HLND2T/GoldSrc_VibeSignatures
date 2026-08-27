# Release operations

The release build is a manual `workflow_dispatch` (`release-build.yml`, `version` plus optional `source_sha` and `mode`).
It can also be triggered by pushing a `v[0-9]*` version tag (tag name is `version`, `source_sha` is the tagged commit,
`mode` is fixed to `new`).
Production authority comes from the allowlisted repository + `win64` Environment + per-version concurrency, not
`GSVIBE_RELEASE_PHASE2_ENABLED` or a GitHub App token.

## State and truth sources

The private stage directory is `PERSISTED_WORKSPACE/release-staging/<version>/<build_id>/`, holding canonical
`manifest.json`, `READY`, `PROMOTION_STARTED`, `PROMOTED.json`, and `PROMOTION_COMPLETE` markers. `pr-index/<pr>.json`
binds the output PR; `completed/<version>/<build_id>.json` is the durable completion record. Only the completion record
plus the tag identity, Release ID, and downloaded asset inventory means the release is complete.

## Protected operations

- `abandon`: `abandon-staged-release.yml` (a `workflow_dispatch`), pre-promotion only, with confirmation
  `ABANDON <version>/<build_id>` and a reason. Any recorded PR is remotely verified before it is closed.
- `cleanup`: `cleanup-completed-release-staging.yml` (a `workflow_dispatch` or daily cron) sweeps only stages with
  `PROMOTION_COMPLETE` and a matching durable completion, atomically renaming them to
  `cleanup-trash/<version>/<build_id>`.
- `republish`: `release-build.yml` with `mode=republish`, requiring the `version` tag to exist; it re-analyzes only the
  outputs affected since the last accepted source.

Preserve failed stages, workflow URL/run/attempt, source/bin SHAs, PR/head/merge identity, tag target, Release ID, and
downloaded hashes.

## Generated-output PR base advancement

An output PR stays valid after `main` advances when:

- the output head is a single-parent commit whose parent is exactly the manifest `source_sha`;
- the current PR base is a descendant of that `source_sha`;
- `source_sha..head` only changes allowlisted generated outputs, including `release-manifests/<version>.json`;
- tracked manifest identity and hashes still match.

The verifier does not rebase the immutable output head onto the new base. GitHub mergeability still blocks conflicting
histories. Merge-time `verify_promotion()` uses the same ancestor rule for the merge first parent. Replacement
build/PR is required only when that ancestor or direct-parent identity is broken.
