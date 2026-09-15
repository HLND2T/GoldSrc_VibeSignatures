---
title: Mod_PointInLeaf locator
type: note
permalink: goldsrc-vibesignatures/locators/mod-pointinleaf
tags:
  - locator
  - engine
  - func
---

# Mod_PointInLeaf

## Symbol

- **Name**: `Mod_PointInLeaf`
- **Category**: `func`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-Mod_PointInLeaf.py`

## Availability

- Declared in 10 engine configs: cof-5936, hl-10210, hl-3248, hl-3266, hl-3329, hl-3647, hl-4554, hl-6153, hl-8684, svencoop-10257.
- Platforms: Windows + Linux (no `platform` gate). Linux engine modules exist only for hl-10210, hl-8684 and svencoop-10257.
- Inlined / absent: none observed — the guard literal has a single owning function in every validated build, and the artifact records that owner.
- Not applicable to cstrike/czero/czeror (no engine module in this repo).

## Predecessors

- None. `find-Mod_PointInLeaf` has no `expected_input`.

## How it is located

`preprocess_common_skill` with a single exact string xref:

- `FULLMATCH:Mod_PointInLeaf: bad model` — the null-node guard (`if (!model->nodes) Sys_Error(...)`) inside the BSP leaf lookup. It belongs to `Mod_PointInLeaf` only, so one owner is enough.

No byte signature participates in discovery. `_inspect_function_via_mcp` emits `func_name / func_sig / func_va / func_rva / func_size`.

## Pitfalls

- The string is short-ish and lives in a hot rendering path, so beware of the shared IDB string-list pollution pitfall if any custom finder rebuilds the string list with a bigger `minlen`.
- The guard literal is the *only* anchor here: there is no structural or signature fallback, so a family that renamed the diagnostic would fail closed rather than silently mis-locate.
- Blob engines (hl-3248..hl-3647) are Windows-only and run against `hw.decrypt.dll`.
