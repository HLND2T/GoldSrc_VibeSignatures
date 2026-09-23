---
title: Snapshot schema and scalar contract
type: architecture
permalink: goldsrc-vibesignatures/notes/snapshot-schema-and-scalar-contract
tags:
- snapshot
- gamesymbols
- scalar
- schema
- publication
---

# Snapshot schema and scalar contract

## Overview

The game-symbol snapshot writer emits schema 8 and readers accept schemas 1–8. Browser JSON datasets and the index are
derived deterministically from that snapshot. This note covers the snapshot schema contract, the numeric-scalar category,
and the trusted rollout that introduced it. The snapshot/metadata pair and its candidate session live in
[[Immutable alias metadata companion]]; gamedata derivation is in [[Canonical gamedata bootstrap]].

## Writer contract (schema 8)

- Config digest version 2, analysis-output contract version 3, UTC publication time, canonical file payloads, and
  path-independent SHA-256/MD5/CRC32/CRC64/size metadata.
- A required boolean `is_blob` per configured binary. `is_blob` is `true` only when the original Windows file fails plain
  PE validation but passes the full Metahook blob decrypt/rebuild/verify pipeline (shared by the snapshot writer and the
  analyzer); plain PE and Linux ELF are `false`, and an invalid binary fails the snapshot instead of being published as
  `false`.
- Schema 7 introduced the required `is_blob`; schema 5 retains its required legacy binary `path`. Scalars require schema 8.
- Restore and verification reject links, path escapes, undeclared or missing YAML, non-canonical bytes, and contract drift.

## Numeric scalars (`category: scalar`)

- Schema 8 / analysis-output contract 3 add `category: scalar`. The artifact contains only `scalar_name` and
  `scalar_value` (uint32); no address or signature is fabricated.
- Consumers use the value directly for the matching binary identity: no image-base adjustment, pointer dereference, or
  runtime scanning. JSON exports `kind: scalar` and preserves the payload; the index stays schema 4.
- The finder independently verifies current-binary dataflow and requires the LLM's semantic mapping to agree — for example
  an optimizing compiler may express a frame stride through LEA/SHL/SUB even when pseudocode shows a constant multiplier,
  so the artifact must not depend on a single IMUL. Conflicting or unsupported evidence is rejected, and a value is never
  borrowed from another build.
- Scalar payloads are rejected under snapshots 1–7 and analysis-output contract 2.

## Browser JSON datasets

- Derived deterministically from the schema-8 snapshot and the schema-1 metadata companion: each dataset is schema 5
  (`<tag>.<sha256>.json`, carrying the per-binary `isBlob` flag) and the index is schema 4.
- The JSON generator and the Pages frontend accept only schema-8 snapshots and schema-5 datasets — there is no
  legacy-dataset compatibility mode. The Vite plugin relays those bytes without re-deriving and never reads live config
  aliases.

## Trusted scalar compatibility rollout

- The trusted PR planner and candidate builder run from the PR base revision, so a prerequisite change must teach them the
  new contract before a feature PR enables it. The prerequisite retained snapshot 7 / analysis-output contract 2 defaults;
  the feature switched the defaults to snapshot 8 / contract 3.
- `gamesymbol_candidate.py build -snapshot-schema-version 8` explicitly selects the supported snapshot 8 / contract 3 pair.
  The builder validates artifacts, builds metadata, and reopens the candidate against that contract; unsupported formats
  fail closed. The ordinary SymbolStore reader still requires its current contract unless a caller explicitly selects
  another supported contract.
- Explicit profile 7 remains available for compatibility callers with non-scalar artifacts; it does not migrate old data or
  relax the current export/UI requirements. Old snapshots must not contain scalar fields: use explicit legacy restore into
  an isolated artifact root, analyze missing current artifacts, and rebuild through the current candidate pipeline. Editing
  the schema number alone is not a migration, and historical archive bytes stay immutable.

## Restore and verification (compatibility/migration)

Snapshot restore is an explicit compatibility/migration operation. The Release no longer publishes snapshot YAML, so a
snapshot comes from a local candidate build. Verification reads, and restore writes, only the explicit artifact root:

```bash
uv run python gamesymbol_snapshot.py verify -gamever cstrike-10210 -snapshot <release-asset.yaml> \
  -bindir bin -artifactdir bin_artifacts
uv run python gamesymbol_snapshot.py check-contract -gamever cstrike-10210 -snapshot <release-asset.yaml> \
  -bindir bin -artifactdir bin_artifacts
uv run python gamesymbol_snapshot.py restore-legacy -gamever cstrike-10210 -snapshot <release-asset.yaml> \
  -bindir bin -artifactdir <compatibility-artifact-root>
```

## Validation

Metadata/candidate/release-bundle tests, the repository-contract suite, and Pages test/lint/build/asset checks cover the
snapshot schema, scalar payloads, JSON derivation, and legacy-reader behaviour.
