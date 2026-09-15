---
title: Mod_LoadSpriteModel locator
type: note
permalink: goldsrc-vibesignatures/locators/mod-loadspritemodel
tags:
  - locator
  - engine
  - func
---

# Mod_LoadSpriteModel

## Symbol

- **Name**: `Mod_LoadSpriteModel`
- **Category**: `func`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-Mod_LoadSpriteModel.py`

## Availability

- Declared in 10 engine configs: cof-5936, hl-10210, hl-3248, hl-3266, hl-3329, hl-3647, hl-4554, hl-6153, hl-8684, svencoop-10257.
- Platforms: Windows + Linux (no `platform` gate). Linux engine modules exist only for hl-10210, hl-8684 and svencoop-10257.
- Inlined / absent: never inlined; the sprite loader is a standalone function in every build. Its *diagnostics* differ per family, which is why two anchor specs exist.
- Not applicable to cstrike/czero/czeror (no engine module in this repo).

## Predecessors

- None. `find-Mod_LoadSpriteModel` has no `expected_input`.

## How it is located

`preprocess_common_skill` with two `FUNC_XREFS_SPECS` tried in order; the first spec that produces a single-owner exact match wins:

1. `FULLMATCH:Mod_LoadSpriteModel: Invalid # of frames: %d\n` — the per-family frame-count guard in the shared (non-SvEngine) sprite loader.
2. `FULLMATCH:Sprite "%s" has wrong version number (%i should be %i)` — SvEngine's rewritten sprite loader reports the version mismatch instead.

No byte signature participates in discovery. `_inspect_function_via_mcp` then emits `func_name / func_sig / func_va / func_rva / func_size`.

## Pitfalls

- The literal present depends on the family, so both specs must stay and keep their order; a rebuild that drops one silently loses the SvEngine branch.
- Both spec strings are matched against the shared IDB string list, so a finder that rebuilds that list with a coarser `minlen` can hide them (shared string-list pollution).
- This artifact is the predecessor of `find-Mod_LoadSpriteModel-decompiles` (svencoop-10257 Linux → `Hunk_AllocName`), which re-verifies the `func_va` from this YAML as a function start. A wrong root breaks that branch too.
- Blob engines (hl-3248..hl-3647) are Windows-only and run against `hw.decrypt.dll`.
