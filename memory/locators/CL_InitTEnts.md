---
title: CL_InitTEnts locator
type: note
permalink: goldsrc-vibesignatures/locators/cl-inittents
tags:
  - locator
  - engine
  - func
---

# CL_InitTEnts

## Symbol

- **Name**: `CL_InitTEnts`
- **Category**: `func`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-CL_InitTEnts.py`

## Availability

- Declared in 10 engine configs: cof-5936, hl-10210, hl-3248, hl-3266, hl-3329, hl-3647, hl-4554, hl-6153, hl-8684, svencoop-10257.
- Platforms: Windows + Linux.
- Inlined / absent: none — always a standalone function. Its *body* differs: CoF keeps `CL_TempEntInit` out of line (so the pool initializer is a visible `call` at the tail), while the canonical HL builds inline the pool initialization into `CL_InitTEnts` instead.

## Predecessors

- None. `find-CL_InitTEnts` has no `expected_input`; it is the root of the temp-entity group.
- It is the predecessor for `find-CL_InitTEnts-calls`, `find-CL_InitTEnts-decompiles` and `find-CL_InitTEnts-studio-decompiles`.

## How it is located

1. `FUNC_XREFS` anchors the function on `FULLMATCH:sprites/shellchrome.spr` — the chrome shell sprite `CL_InitTEnts` precaches at the very end of the function (immediately before the pool init). The literal exists on every engine platform and is unique.
2. The owning function of that string xref is `CL_InitTEnts`.
3. Emitted fields: `func_name`, `func_sig`, `func_va`, `func_rva`, `func_size`, with `func_sig_allow_across_function_boundary:true` baked into `generate_yaml_desired_fields`.

## Pitfalls

- The anchor is the shellchrome *sprite path*, not a name string — do not substitute a nearby `sprites/*.spr` literal; `CL_InitTEnts` precaches ~9 sprites but only this one is its final, unique anchor.
- On CoF the function ends with `mov cl_sprite_shell, eax` + `call CL_TempEntInit`; on HL builds the same tail is the inlined memset/next-pointer loop. Either way the *function* is stable, but do not expect a `CL_TempEntInit` call to exist here.
- Because the signature is allowed across a function boundary, a rebuilt artifact may legitimately span GNU align padding into the next function on Linux.
