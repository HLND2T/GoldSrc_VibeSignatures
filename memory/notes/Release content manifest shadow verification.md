---
title: Release content manifest shadow verification
type: architecture
permalink: goldsrc-vibesignatures/notes/release-content-manifest-shadow-verification
tags:
- release
- provenance
- git-tree
- shadow
---

# Release content manifest shadow verification

## Overview

Release Phase 1 builds schema-1 canonical content manifests from exact default-branch Git objects. It is a read-only provenance layer and does not own canonical snapshot, metadata, or gamedata publication.

## Responsibilities

- Bind exact source commit and `bin` gitlink.
- Cross-check canonical snapshot, immutable metadata companion, raw analysis config, and canonical gamedata manifest.
- Bind config, generator, workflow, and release-tool contract digests.
- Inventory the current tag's snapshot, metadata, and gamedata blobs using path, Git mode, size, and raw SHA-256.
- Emit repeatable three-tag shadow evidence with a `new` mode decision.

## Architecture

`release_workflow.py` delegates Git-object reads to `release_workflow_lib/git_objects.py`, content cross-checking to `release_workflow_lib/content.py`, strict schema handling to `release_workflow_lib/manifest.py`, and multi-tag evidence generation to `release_workflow_lib/shadow.py`.

The tracked-content inventory deliberately excludes `release-manifests/<tag>.json`; otherwise the manifest would hash itself. Candidate sessions, Actions artifacts, worktree globs, inode/mtime, and local READY pointers are not release truth sources.

## Dependencies

- `gamesymbol_snapshot_lib.codec` for canonical snapshot validation.
- `gamesymbol_snapshot_lib.metadata` for companion binding and owner projection validation.
- `gamedata_contract` for canonical manifest and generator contract validation.
- Git tree/blob identities at the exact source SHA.

## Notes

The shadow workflow has only `contents: read` and uploads evidence artifacts. It cannot push refs or contents, create output PRs or tags, or publish Releases. Generated-output PR and promotion remain a separate later phase gated by protected-repository exercises and external GitHub settings.

## Verification

Unit tests cover deterministic canonical output, self-exclusion, metadata/config/gamedata/generator tampering, extra payloads, Git mode changes, schema/canonical failures, default-branch drift, and three-tag shadow behavior.

## Cross-platform config identity

Trigger signal: a Windows-built gamedata manifest passes local candidate tests but fails exact Git-blob shadow verification or Ubuntu rebuild comparison.

Root cause: Windows worktree CRLF bytes and Git's normalized LF blob produce different raw SHA-256 values when config identity hashes unnormalized filesystem bytes.

Correct approach: `analysis_config_sha256()` normalizes CRLF to LF, rejects bare CR, and repository attributes pin `configs/*.yaml` to LF. Candidate sessions, gamedata manifests, Ubuntu rebuilds, and release Git-blob verification then share one stable digest.

Verification: unit-test LF/CRLF equivalence and bare-CR rejection, backfill tracked manifests, then run real three-tag shadow verification from a temporary exact Git tree.