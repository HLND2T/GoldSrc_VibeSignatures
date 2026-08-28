---
title: Immutable alias metadata companion
type: architecture
permalink: goldsrc-vibesignatures/notes/immutable-alias-metadata-companion
tags:
- gamesymbols
- metadata
- pages
- publication
---

# Immutable alias metadata companion

## Overview

Each tracked `gamesymbols/<tag>.yaml` snapshot has a schema-1 `gamesymbols/<tag>.metadata.yaml` companion. The companion freezes only display aliases plus resolved `module + platform + artifact` owner identities. Pages does not read live configs.

## Responsibilities

- `gamesymbol_snapshot_lib/metadata.py` generates, parses, verifies, compares, and atomically writes canonical companion bytes.
- `gamesymbol_metadata.py` exposes `generate`, `verify`, and `compare`.
- `gamesymbol_snapshot_lib/candidate.py` binds snapshot and metadata paths, hashes, filesystem identities, and the metadata snapshot hash in session schema 2.
- Pair publication uses a same-directory recovery journal. Intermediate mismatches fail verification; the Git tree is the external atomic boundary.
- `pages/gameSymbolsPlugin.ts` requires the companion and attaches aliases only by exact owner identity.

## Contract

The companion binds exact canonical snapshot bytes with lowercase raw SHA-256, config digest version 2, and the raw config contract SHA-256. Alias strings normalize to a non-empty ordered list; empty, duplicate, non-string, unknown, or duplicate owners fail closed. Module/symbol list order follows config declaration order; artifacts use fixed Windows then Linux order.

## Files and callers

- `gamesymbol_snapshot_lib/metadata.py`
- `gamesymbol_metadata.py`
- `gamesymbol_snapshot_lib/candidate.py`
- `gamesymbol_snapshot_lib/pr_cli.py`
- `.github/workflows/gamesymbol-pr-validation.yml`
- `pages/gameSymbolsPlugin.ts`

## Validation

Run the Python metadata/candidate/planner tests, repository-contract suite, and Pages test/lint/build/asset verification. A zero-symbol tag may remain config-only before its first release, but release publication may create its snapshot and companion. Once the snapshot exists, the companion is mandatory and follows the same canonical binding contract as every other published tag.
