---
title: Mod_LoadStudioModel locator
type: note
permalink: goldsrc-vibesignatures/locators/mod-loadstudiomodel
tags:
  - locator
  - engine
  - func
---

# Mod_LoadStudioModel

## Symbol

- **Name**: `Mod_LoadStudioModel`
- **Category**: `func`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-Mod_LoadStudioModel.py`

## Availability

- Declared in 10 engine configs: cof-5936, hl-10210, hl-3248, hl-3266, hl-3329, hl-3647, hl-4554, hl-6153, hl-8684, svencoop-10257.
- Platforms: Windows + Linux (no `platform` gate). Linux engine modules exist only for hl-10210, hl-8684 and svencoop-10257.
- Inlined / absent: never inlined; the studio (MDL) loader is a standalone function in every build.
- Not applicable to cstrike/czero/czeror (no engine module in this repo).

## Predecessors

- None. `find-Mod_LoadStudioModel` has no `expected_input`.

## How it is located

`preprocess_common_skill` with a single exact string xref:

- `FULLMATCH:bogus` — the literal the studio loader passes to `Sys_Error` when the studio header fails its length sanity check (`bogus` is the classic "header length is bogus" abort). It has exactly one owning function, `Mod_LoadStudioModel`, on every validated build.

No byte signature participates in discovery. `_inspect_function_via_mcp` emits `func_name / func_sig / func_va / func_rva / func_size`.

## Pitfalls

- `bogus` is only **5 characters** long, i.e. exactly at the IDA default minimum. This symbol is the canonical victim of shared IDB string-list pollution: `find-GL_Shutdown` (and any other custom finder) that calls `idautils.Strings().setup(minlen=6, ...)` without restoring the previous options permanently hides `bogus` from the shared template's `Strings(default_setup=False)` iteration. The failure signature is a ~0.2 s no-match (`preprocessor_completed status=failed`) with no crash, and it is *batch-order dependent* — `find-GL_Shutdown` running earlier in the same worker session is what triggers it.
- Consequence: never add a non-restoring `strings.setup()` to the shared path, and keep the idempotent raw-segment scan documented in the pollution note as the safe alternative for short literals.
- The anchor is a 5-byte literal, so it also must not be "strengthened" into a longer literal that does not exist in some families — no fallback spec is defined here.
