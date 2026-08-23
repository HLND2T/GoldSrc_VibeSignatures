---
title: Release staging, promotion, and recovery
type: note
permalink: goldsrc-vibesignatures/release-staging-promotion-recovery
---

# Release staging, promotion, and recovery

## Overview

Phase 2 separates stable release content identity from build-attempt and promotion identity. Source PRs retain authority
for snapshot, metadata, and gamedata; the release App only creates a one-file manifest commit, its output PR, immutable
tag, verified Release assets, and completion records.

## Responsibilities

- Route every output-like PR to the read-only output verifier and keep one final `pr-validate`.
- Hash-chain private stage markers and bind repository/source/branch/PR/head/base/merge/tag/Release identities.
- Require a direct-parent output head and a two-parent merge commit.
- Build deterministic assets, exclude checksum self-reference, and verify downloaded hashes.
- Keep retry, resume-promotion, republish, abandon, repair-index, cleanup, and reconcile semantically distinct.

## Involved Files

- `pull_request_route.py`
- `release_workflow.py`
- `release_workflow_lib/output.py`
- `release_workflow_lib/staging.py`
- `release_workflow_lib/promotion.py`
- `release_workflow_lib/recovery.py`
- `.github/workflows/release-build.yml`
- `.github/workflows/release-output-validation.yml`
- `.github/workflows/release-promotion.yml`
- `.github/workflows/release-operations.yml`

## Architecture

`source SHA -> direct-parent manifest head -> output PR/READY -> two-parent merge -> PROMOTION_STARTED -> annotated tag +
draft Release -> deterministic assets/download verification -> PROMOTED -> durable completion -> PROMOTION_COMPLETE ->
recoverable cleanup trash`.

The original promotion workflow repository/path/ref is bound at `PROMOTION_STARTED` so a resume rebuilds identical
provenance even when the operator workflow itself has advanced.

## Recovery Notes

- Trigger signal: a marker exists without its successor, a PR index is missing, or remote tag/Release state differs.
- Root constraint: never switch build ID after `PROMOTION_STARTED`; never treat Actions artifacts as truth.
- Correct action: use the matching explicit operation and exact identities; preserve diagnostics append-only.
- Verification: load the full marker hash chain, recompute approval/content/assets, then compare remote tag, Release ID, and
  downloaded hashes with durable completion.
- Scope: Phase 2 generated-output releases only; production activation remains externally gated.
