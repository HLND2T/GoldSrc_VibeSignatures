---
title: R_LoadSkys locator
type: note
permalink: goldsrc-vibesignatures/locators/r-loadskys
tags:
  - locator
  - engine
  - func
---

# R_LoadSkys

## Symbol

- **Name**: `R_LoadSkys`
- **Category**: `func`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-R_LoadSkys.py`

## Availability

- Declared in 9 engine configs: cof-5936, hl-10210, hl-3248, hl-3266, hl-3329, hl-3647, hl-4554, hl-6153, hl-8684.
- Platforms: Windows + Linux (no `platform` gate); Linux engine modules exist only for hl-10210 and hl-8684.
- Inlined / absent: not applicable to svencoop-10257 — SvEngine prints a one-space banner from its own internal sky loader, so this finder is deliberately not registered there.
- Not applicable to cstrike/czero/czeror (no engine module in this repo).

## Predecessors

- None. `find-R_LoadSkys` has no `expected_input`.

## How it is located

`preprocess_common_skill` with a single exact string xref:

- `FULLMATCH:SKY:  ` — the `engine/gl_warp.c` banner printed before the six sky faces are loaded. The needle has **two trailing spaces and no newline**, and the exact match is what keeps it distinct from SvEngine's one-space variant.

No byte signature participates in discovery. `_inspect_function_via_mcp` emits `func_name / func_sig / func_va / func_rva / func_size`.

## Pitfalls

- Trailing whitespace is load-bearing: `SKY:` alone, or the one-space variant, would either match nothing or match SvEngine's internal loader.
- Partial registration is a real trap here. `ida_analyze_bin.py -allgamever -skill find-R_LoadSkys` aborts at svencoop-10257 with `Skill 'find-R_LoadSkys' not found` and silently skips every config after it (cof-5936 was the observed casualty), which only the `bin_artifact` inventory check catches. Validate per registered gamever instead.
- Because the anchor is a bare 5-character-ish literal, the shared IDB string-list pollution pitfall also applies; there is no structural fallback.
- Blob engines (hl-3248..hl-3647) are Windows-only and run against `hw.decrypt.dll`.
