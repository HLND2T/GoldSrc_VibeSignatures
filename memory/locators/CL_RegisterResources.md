---
title: CL_RegisterResources locator
type: note
permalink: goldsrc-vibesignatures/locators/cl-registerresources
tags:
  - locator
  - engine
  - func
---

# CL_RegisterResources

## Symbol

- **Name**: `CL_RegisterResources`
- **Category**: `func`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-CL_RegisterResources.py`

## Availability

- Declared in 10 engine configs: cof-5936, hl-10210, hl-3248, hl-3266, hl-3329, hl-3647,
  hl-4554, hl-6153, hl-8684, svencoop-10257.
- Platforms: no `platform:` gating; only hl-10210, hl-8684 and svencoop-10257 declare
  `module_linux: hw.so`, the other seven configs are Windows-only here.
- Inlined / absent: always present. The diagnostic literal it owns can also appear inside
  functions that inlined `CL_ReallocateDynamicData` (see `CL_ReallocateDynamicData`).

## Predecessors

- None for this finder.
- It is the **required predecessor** for `find-CL_RegisterResources-decompiles`
  (registered in svencoop-10257 only), which emits `R_NewMap`.

## How it is located

Pattern A string xref in `FUNC_XREFS`:

1. `xref_strings: ["FULLMATCH:Setting up renderer...\n"]` — exact equality. The docstring
   states the diagnostic belongs to resource registration, which calls `R_NewMap`.
2. Exactly one candidate function; emit `func_name`, `func_sig`, `func_va`, `func_rva`,
   `func_size`.

## Pitfalls

- The same literal is an `exclude_strings` entry in `find-CL_ReallocateDynamicData` (GCC
  inlines that allocator here). Do not "fix" one finder by tightening the other: the
  exclusion exists so the *allocator* anchor does not land on this function.
- Discovery never consumes an old artifact signature (`old_yaml_map=None`).
- On Sven Co-op this function is also the only anchor for `R_NewMap` (`window02_1` is gone
  there): the `-decompiles` finder must locate the renderer-reset call inside this body. The
  `Hunk_Check` call that follows it is explicitly not the target.
- CoF (`cof-5936`) is Windows-only in this repo.
