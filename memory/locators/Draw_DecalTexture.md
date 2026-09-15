---
title: Draw_DecalTexture locator
type: note
permalink: goldsrc-vibesignatures/locators/draw-decaltexture
tags:
  - locator
  - engine
  - func
---

# Draw_DecalTexture

## Symbol

- **Name**: `Draw_DecalTexture`
- **Category**: `func`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-Draw_DecalTexture.py`

## Availability

- Declared in 10 engine configs: cof-5936, hl-10210, hl-3248, hl-3266, hl-3329,
  hl-3647, hl-4554, hl-6153, hl-8684, svencoop-10257.
- Platforms: Windows + Linux. The producer declares no `platform` gating and the symbol is
  declared without a `platform` key in every config, including svencoop-10257.
- Inlined / absent: none observed.

## Predecessors

- None. No `expected_input`, no other symbol is consumed.

## How it is located

1. `preprocess_common_skill` with one `func_xrefs` entry and a single exact-match string:
   `FULLMATCH:Failed to load custom decal for player #%i:%s using default decal 0.\n`
   (`FULLMATCH:` forces C-string equality; a plain query would be a substring match).
2. Every function that references that string item is collected via
   `_functions_referencing` → `_ensure_function_owner`, which backtracks a single direct-call
   entry when IDA never promoted the owner — so an un-promoted body still resolves.
3. Exactly one candidate must remain; `len(items) != 1` makes the finder return None and
   write nothing. `xref_gvs` / `xref_signatures` / `xref_funcs` are empty, so this literal
   is the only anchor.
4. `func_name` / `func_sig` / `func_va` / `func_rva` / `func_size` are written to
   `Draw_DecalTexture.{platform}.yaml`.

## Pitfalls

- `engine/cl_main.c` falls back to the default decal on this diagnostic; it is the only
  owner of the literal, which is precisely why the anchor is safe — but uniqueness is still
  enforced, not assumed.
- The literal must exist as a C string item in the IDB string list. Indexing uses the
  project's shared string list; see the note on shared IDB string-list pollution — a stale
  or polluted list can hide the item.
- No platform-specific literal variants exist: the same anchor covers Windows and Linux and
  the SvEngine branch, so no `-svencoop` producer is needed.
