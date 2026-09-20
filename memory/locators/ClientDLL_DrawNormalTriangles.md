---
title: ClientDLL_DrawNormalTriangles locator
type: note
permalink: goldsrc-vibesignatures/locators/clientdll-drawnormaltriangles
tags:
  - locator
  - engine
  - func
---

# ClientDLL_DrawNormalTriangles

## Symbol

- **Name**: `ClientDLL_DrawNormalTriangles`
- **Category**: `func`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-r_refdef-ClientDLL_DrawNormalTriangles.py`
- **Source**: `engine/cdll_int.c`:
  `if (cl_funcs.pDrawNormalTriangles) cl_funcs.pDrawNormalTriangles(); tri.RenderMode(kRenderNormal);`

## Availability

- All 11 engine configs, every declared platform.

## Predecessors

- `CL_SetDevOverView` and `cl_funcs`.

## How it is located

Among the scene renderer's direct callees (PLT-resolved), exactly one satisfies **both**:

1. it references exactly one `cl_funcs` member — `pDrawNormalTriangles`, `+0x58` on every
   validated build; and
2. it additionally dispatches through a function pointer that is *not* a `cl_funcs` member, which
   is the trailing `tri.RenderMode(kRenderNormal)`.

## Pitfalls

- Condition 2 is mandatory. On svencoop-10257 Windows `ClientDLL_IsThirdPerson` (`cl_funcs+0x3c`)
  is also a direct renderer callee referencing exactly one member; it has no trailing dispatch.
- `+0x58` is stable across all builds but is *derived*, not asserted: hardcoding the offset would
  break the moment a build reorders `cldll_func_t`.
- Validation evidence: hl-10210 W `0x10196d80` / L `0x158a20`, svencoop-8948 L `0x17bcf0`
  (`_Z29ClientDLL_DrawNormalTrianglesv` in the symbol table).

## Relations

- relates_to [[r_refdef]]
- relates_to [[cl_funcs]]
