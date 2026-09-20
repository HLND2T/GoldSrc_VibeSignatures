---
title: ClientDLL_DrawTransparentTriangles locator
type: note
permalink: goldsrc-vibesignatures/locators/clientdll-drawtransparenttriangles
tags:
  - locator
  - engine
  - func
---

# ClientDLL_DrawTransparentTriangles

## Symbol

- **Name**: `ClientDLL_DrawTransparentTriangles`
- **Category**: `func`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-ClientDLL_DrawTransparentTriangles.py`
- **Source**: `engine/cdll_int.c`, the forwarding stub that calls the client's
  `HUD_DrawTransparentTriangles`. Confirmed by the retained `.symtab` of
  hl-10210, hl-8684 and svencoop-8948 `hw.so`.

## Availability

- All 11 engine configs, every declared platform.

## Predecessors

- `R_DrawTEntitiesOnList.{platform}.yaml` and `cl_funcs.{platform}.yaml`.

## How it is located

The transparent-entity loader is its only caller, so the target is the unique
direct callee that is tiny and references exactly one `cl_funcs` member
(`pDrawTransparentTriangles`). `cl_funcs_pDrawTransparentTriangles` is that
member's own address, read from the same instruction.

The derivation deliberately differs from `ClientDLL_DrawNormalTriangles`, which
is found among the *scene renderer's* direct callees. Both forwarders have the
same shape and both end in `tri.RenderMode(kRenderNormal)`, so keying on the
renderer would have produced two candidates; keying on the loader separates them
by caller instead.

## Pitfalls

- The global's signature roots on **the located forwarder**, not on
  `R_DrawTEntitiesOnList`: the member read is inside the forwarder, so
  `write_located_globals` would reject a loader-owned span.
- The `cl_funcs` offset is derived, never hardcoded — `cldll_func_t` is not
  guaranteed to keep its layout. `pDrawTransparentTriangles` lands at `+0x5c`
  (hl-10210 Linux) next to `pDrawNormalTriangles` at `+0x58`.
- SvEngine routes the call through a PLT stub; `resolve_elf_plt` handles it, and
  the member read is GOT-relative, so the artifact carries `gv_pic_addend`.
- Validation evidence: hl-10210 L `0x158a40`, hl-8684 L `0x1b0360`,
  svencoop-8948 L `0x17bd20` (`_Z34ClientDLL_DrawTransparentTrianglesv` in the
  symbol table).

## Relations

- relates_to [[cl_funcs_pDrawTransparentTriangles]]
- relates_to [[R_DrawTEntitiesOnList]]
- relates_to [[cl_funcs]]
