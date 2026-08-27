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

## Recovery Notes

- Trigger signal: a stage marker exists without its successor, a PR index is missing, or remote tag/Release state differs.
- Root constraint: never switch build ID after `PROMOTION_STARTED`; never treat Actions artifacts as truth.
- Correct action: use the matching explicit operation and exact identities; preserve diagnostics append-only.
- Verification: recompute tracked output/bin inventories and compare remote tag/Release with durable completion.
- Scope: multi-gamever versioned releases only; `mode=republish` re-analyzes only the invalidated outputs.
