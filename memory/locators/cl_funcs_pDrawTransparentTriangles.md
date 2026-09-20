---
title: cl_funcs_pDrawTransparentTriangles locator
type: note
permalink: goldsrc-vibesignatures/locators/cl-funcs-pdrawtransparenttriangles
tags:
  - locator
  - engine
  - gv
---

# cl_funcs_pDrawTransparentTriangles

## Symbol

- **Name**: `cl_funcs_pDrawTransparentTriangles`
- **Category**: `gv`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-ClientDLL_DrawTransparentTriangles.py`
- **Source**: the `pDrawTransparentTriangles` slot of the engine's `cldll_func_t`
  (`engine/APIProxy.h`), assigned in `engine/cdll_int.c` from
  `GetProcAddress(hClientDLL, "HUD_DrawTransparentTriangles")` and consumed by
  `ClientDLL_DrawTransparentTriangles`.

## Availability

- All 11 engine configs, every declared platform.

## Predecessors

- `R_DrawTEntitiesOnList.{platform}.yaml` and `cl_funcs.{platform}.yaml`.

## How it is located

The single `cl_funcs` member read inside the recovered
[[ClientDLL_DrawTransparentTriangles]] forwarder. The address is never computed
as `cl_funcs` plus a fixed offset.

## Pitfalls

- `cl_funcs` itself is a separate artifact produced by
  `find-ClientDLL_Init-cl_funcs`; this slot is validated to lie inside
  `[cl_funcs, cl_funcs + 0x120)` and to be four-byte aligned before it is
  accepted.
- The name is MetaHookSv's; the engine has no symbol for the slot.
- Validation evidence: hl-10210 L `0xf77fdc` (`cl_funcs` `0xf77f80` + `0x5c`),
  hl-8684 L `0xf1f3dc`, svencoop-8948 L `0x30d209c`.

## Relations

- relates_to [[ClientDLL_DrawTransparentTriangles]]
- relates_to [[cl_funcs]]
