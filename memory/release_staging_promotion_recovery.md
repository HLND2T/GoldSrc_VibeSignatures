---
title: Release staging, promotion, and recovery
type: note
permalink: goldsrc-vibesignatures/release-staging-promotion-recovery
---

# Release staging, promotion, and recovery

## Overview

The release build (`release-build.yml`, manual `version=vYYYYMMDD[a-z]` dispatch) owns `gamesymbols/**` and
`gamedata/**` for every game version. It analyzes all game versions on the self-hosted runner, publishes candidates
into the working tree, stages them under `PERSISTED_WORKSPACE/release-staging/<version>/<build_id>/`, and opens one
generated-output PR (`gamesymbols/build/<version>`). Merging that PR promotes a single versioned tag and GitHub Release.

## Responsibilities

- Keep source-owned `repository-contract` independent of release-owned `gamesymbols/**` and `gamedata/**`; source PRs may change configs and finders without regenerating published output.
- Run the separate `generated-output-contract` after release candidate publication and before staging. The trusted output-PR verifier reuses the same validator against the exact output head, requiring config tags, snapshots, metadata, gamedata, config digests, artifact paths, and generator bindings to converge.

- Gate output PRs through `validate-generated-output-pr.yml` (bot author, same repo, `gamesymbols/build/` branch).
- Hash-chain private stage markers and bind version/source/branch/PR/head/merge identities.
- Require a direct-parent output head whose parent equals manifest `source_sha`, a current PR/merge base that
  descends from that `source_sha`, and a two-parent merge commit. Default-branch advancement is not itself stale.
- Promote accepted binaries transactionally into `PERSISTED_WORKSPACE/bin/<gamever>` under a per-version lock.
- Keep abandon, cleanup-unmerged, and cleanup-completed semantically distinct.

## Involved Files

- `release_workflow.py`
- `release_workflow_lib/manifests.py`
- `release_workflow_lib/staging.py`
- `release_workflow_lib/promotion.py`
- `release_workflow_lib/validation.py`
- `release_workflow_lib/cli.py`
- `release_workflow_lib/sync_accepted_bin.py`
- `idb_cache_release.py`
- `.github/workflows/release-build.yml`
- `.github/workflows/validate-generated-output-pr.yml`
- `.github/workflows/promote-release-after-output-merge.yml`
- `.github/workflows/abandon-staged-release.yml`
- `.github/workflows/cleanup-completed-release-staging.yml`

## Architecture

`source SHA -> analyze all game versions -> publish candidates -> stage-build (per-version stage dir) -> output PR ->
READY -> two-parent merge -> PROMOTION_STARTED -> promote-bin -> tag + Release -> durable completion ->
PROMOTION_COMPLETE -> recoverable cleanup trash`.

## Accepted-bin reuse and persistence boundary

- Both the release consumer and the warm-IDB producer run `materialize-accepted-bin --all-gamevers` before their work. It overlays each durable accepted tree from `PERSISTED_WORKSPACE/bin/<gamever>` into the checkout. Durable state includes binaries, side files, and per-node symbol YAML, but excludes recoverable IDA/BinSync state such as `.i64`, `.idb`, `.bsproj`, and `.binsync.json`.
- Normal `ida_analyze_bin.py` scheduling skips a node when its declared outputs already exist. For `mode=republish`, `invalidate-republish` compares the previously accepted manifest `source_sha` with the new immutable source and removes only affected symbol YAML before analysis. Unchanged accepted artifacts are therefore reused automatically.
- The tracked `gamesymbols/<gamever>.yaml` snapshot is not materialized as an analysis baseline. Candidate construction repacks the actual `bin/<gamever>` tree and reads the tracked snapshot only to inherit `last_publish_time`. The release workflow's downloaded Actions artifact carries the exact warm-IDB cache selection, not symbol truth; see [[Immutable warm IDB cache generations]].
- Successful analysis and candidate publication do not modify the accepted root. `stage-build` first copies the durable bin trees to `PERSISTED_WORKSPACE/release-staging/<version>/<build_id>/bin/` and binds them to the private/tracked manifests and `READY` marker.
- `PERSISTED_WORKSPACE/bin/<gamever>` changes only after the generated-output PR is actually merged and `verify-promotion` accepts the same-repository trusted PR, default-branch base, `gamesymbols/build/<version>` identity, direct-parent output head, two-parent merge, tracked output inventory, and staged bin hash. `promote-bin` then writes `PROMOTION_STARTED` and transactionally swaps each differing gamever tree under the release and accepted-bin locks; identical inventories are skipped.
- `promote-bin` runs before tag creation, GitHub Release publication, and `PROMOTION_COMPLETE`. If a later step fails, accepted bin may already contain the promoted tree; recovery must resume the same `version/build_id` rather than rebuild or abandon it. A build failure, an unmerged/closed output PR, or failed promotion verification leaves accepted bin unchanged.
- `sync-accepted-bin` is a separate explicit maintenance command that mirrors `bin/<gamever>` into the accepted root while excluding recoverable analysis state. No official workflow calls it, so it is not part of the normal release promotion path.

## Recovery Notes

- Trigger signal: a stage marker exists without its successor, a PR index is missing, or remote tag/Release state differs.
- Root constraint: never switch build ID after `PROMOTION_STARTED`; never treat Actions artifacts as truth.
- Correct action: use the matching explicit operation and exact identities; preserve diagnostics append-only.
- Verification: recompute tracked output/bin inventories and compare remote tag/Release with durable completion.
- Scope: multi-gamever versioned releases only; `mode=republish` re-analyzes only the invalidated outputs.
