# Release operations

The release build is a manual `workflow_dispatch` (`release-build.yml`, `version` plus optional `source_sha` and `mode`).
Production authority comes from the allowlisted repository + `win64` Environment + per-version concurrency, not
`GSVIBE_RELEASE_PHASE2_ENABLED` or a GitHub App token.

## Credential and permission boundary

- `release-build.yml` keeps its default `${{ github.token }}` read-only (`actions: read`, `contents: read`, and
  `pull-requests: read`). Exact source checkout, Git authentication, output-branch push, and PR creation use the
  `win64` Environment secret `HLND2T_GH_TOKEN`.
- The PAT needs repository `Contents: Read and write`, `Pull requests: Read and write`, and `Metadata: Read`; its owner
  must be an `OWNER`, `MEMBER`, or repository `COLLABORATOR`. Workflow `permissions` do not grant or widen PAT scopes.
- Output PR validation receives no PAT and stays at `contents: read`. Merge-time promotion uses `${{ github.token }}`
  with `contents: write` and `pull-requests: read` for the immutable tag and GitHub Release.
- `GSVIBE_BIN_TOKEN`, where still configured for source-PR or warmup workflows, is a private-submodule read credential.
  It is not the release publication credential.

Never print, persist, upload, or copy the PAT value into logs, artifacts, manifests, staging, caches, or Git config
diagnostics. Rotate or revoke it through the `win64` Environment and record the owner, expiry, SSO authorization, and
rotation owner outside the repository.

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

## Known promotion storage gate

`PERSISTED_WORKSPACE` currently exists only as a `win64` Environment secret; the hosted Ubuntu `verify` job does not
declare that Environment, so its `${{ secrets.PERSISTED_WORKSPACE }}` reference resolves empty. Even if supplied as a
repository secret, the job passes `$STAGING_ROOT/release-staging` to `verify-promotion` while the private stage is
produced on the Windows self-hosted runner, and no artifact or shared mount bridges those filesystems. Production
promotion acceptance therefore remains blocked until storage/topology is resolved and exercised; repository tests and
the PAT migration do not prove that path.
