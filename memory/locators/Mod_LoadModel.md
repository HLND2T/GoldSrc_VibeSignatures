---
title: Mod_LoadModel locator
type: note
permalink: goldsrc-vibesignatures/locators/mod-loadmodel
tags:
  - locator
  - engine
  - func
---

# Mod_LoadModel

## Symbol

- **Name**: `Mod_LoadModel`
- **Category**: `func`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-Mod_LoadModel.py`

## Availability

- Declared in 10 engine configs: cof-5936, hl-10210, hl-3248, hl-3266, hl-3329, hl-3647, hl-4554, hl-6153, hl-8684, svencoop-10257.
- Platforms: Windows + Linux (no `platform` gate). Linux engine modules exist only for hl-10210, hl-8684 and svencoop-10257.
- Inlined / absent: on optimized Linux GoldSrc builds the loading body survives as a split function (`Mod_LoadModel.part.N`, register-argument prologue such as `push ebp; mov ebp, ecx; push edi/esi/ebx; mov ebx, eax`) while the public `Mod_LoadModel` symbol is only a wrapper. The artifact deliberately points at the part-function, which is the required control-flow root — never "fix" it back to the wrapper.
- Not applicable to cstrike/czero/czeror (no engine module in this repo).

## Predecessors

- None. `find-Mod_LoadModel` has no `expected_input`.

## How it is located

Plain `preprocess_common_skill` with two `FUNC_XREF_ALTERNATIVES`, tried in order; the first alternative that yields a single-owner match wins. Each alternative is an exact (`FULLMATCH:`) string-xref owned by exactly one function:

1. `Mod_NumForName: %s not found` — classic GoldSrc and CoF loading body.
2. `Mod_LoadModel: Could not load '%s': File not found` — SvEngine's rewritten dispatcher.

No byte signature participates in discovery. On success `_inspect_function_via_mcp` emits `func_name / func_sig / func_va / func_rva / func_size`.

## Pitfalls

- The literal that exists is family-dependent, so both alternatives must stay in the list and stay ordered — replacing one with "the" literal silently loses whole tags.
- The xref-string step reads the shared IDB string list. A finder that rebuilds it with a larger `minlen` (see the shared string-list pollution note) can hide these literals and make this skill fail with a fast no-match, with no crash diagnostic.
- This artifact is the predecessor of three downstream skills (`find-Mod_LoadModel-decompiles` → `FS_Open` plus `loadname`/`loadmodel`, `find-Mod_LoadModel-brushmodel-decompiles` → `Mod_LoadBrushModel`, `find-Mod_LoadModel_to_FS_Open_callsites`), all of which locate `Mod_LoadModel` again by `func_va` and re-verify that the VA is a function *start*. A wrong (wrapper) root breaks all three at once.
- Blob engines (hl-3248..hl-3647) analyze `hw.decrypt.dll`; the artifact VA must be re-resolved inside that IDB, so `func_va >= image_base` is enforced by consumers.
