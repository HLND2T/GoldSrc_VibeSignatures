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

Every release-bundle `gamesymbols/<tag>.yaml` snapshot has a schema-1 `<tag>.metadata.yaml` companion. The companion
freezes display aliases plus resolved `module + platform + artifact` owner identities. Neither file is Git-versioned;
Pages downloads the pair from a published GitHub Release and never reads live configs.

## Responsibilities

- `gamesymbol_snapshot_lib/metadata.py` generates, parses, verifies, compares, and atomically writes canonical companion
  bytes.
- `gamesymbol_snapshot_lib/candidate.py` binds snapshot/metadata paths, hashes, filesystem identities, and the metadata
  snapshot hash in one candidate session.
- Local pair publication uses a same-directory recovery journal in explicit release staging.
- `release_bundle.py` binds the pair into the closed bundle; hosted verification plus the published Release is the external
  publication boundary.
- `pages/gameSymbolsPlugin.ts` requires the downloaded companion and attaches aliases only by exact owner identity.

## Contract

The companion binds exact canonical snapshot bytes with lowercase raw SHA-256, config digest version 2, and the raw config
contract SHA-256. Alias strings normalize to a non-empty ordered list; empty, duplicate, non-string, unknown, or duplicate
owners fail closed. Module/symbol order follows config declaration order; artifacts use fixed Windows then Linux order.

## Validation

Run metadata/candidate/release-bundle tests, repository-contract, and Pages test/lint/build/asset verification. A
published snapshot always requires its matching companion, including zero-symbol tags.
