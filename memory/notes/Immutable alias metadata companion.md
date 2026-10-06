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

### Module filenames (MetaHookSv issue #903)

Analysis module declarations may set `alias_windows` / `alias_linux` to ordered filename lists. These are runtime binary
filenames, separate from a symbol's display `alias`. The existing Windows client declarations list `client_orig.dll`,
`client_original.dll`, and `client_org.dll`; engine and Linux defaults are unchanged. Empty lists are omitted from metadata.

The schema-1 companion module optionally appends `binary_aliases: {windows: [...]}` after `symbols`. Such a module may have
an empty `symbols` list. Parsing validates filenames, platform order, and the module/platform's presence in the bound
snapshot binaries. Old companions retain their original representation. The JSON exporter reads only these frozen values
and emits `binaries.<module>.<platform>.alias` in the schema-5 dataset; no snapshot/index schema bump or live-config lookup
is involved. Config changes still change the existing config digest, requiring the normal snapshot/metadata rebuild.

Trigger/constraint: a proxy `client.dll` can load an unchanged original under another name. The alias belongs to the same
binary CRC64 and never supplies a proxy hash or an alternate RVA. Consumers must use the loaded alias module's image base
after CRC64 verification. Published datasets remain immutable; regenerate through the ordinary release pipeline, never
patch deployed JSON or historical release bytes. Metadata/JSON tests cover optional compatibility, invalid names, missing
owners, and deterministic export after the live config changes.

Local verification (2026-10-06): 60 metadata/JSON/candidate/snapshot-contract/release-bundle/repository tests and 109 planner
tests passed. The real local `cstrike-10210` binary/artifacts successfully traversed snapshot packing, metadata generation,
JSON export, and MetaHookSv's BulletPhysics/CaptionMod pruning and validation, retaining the three aliases and both reported
symbols (`g_iUser1`, `g_LocationColor`). Pages passed 50 tests, 5 E2E cases, lint, build, and asset verification. Python format
and the 15 changed YAML checks passed; an additional Ruff lint check still reports five pre-existing planner findings,
confirmed against HEAD (import order, one unused variable, three pairwise suggestions). No actual csldr or release
publication was performed.

## Validation

Run metadata/candidate/release-bundle tests, repository-contract, and Pages test/lint/build/asset verification. A
published snapshot always requires its matching companion, including zero-symbol tags.
