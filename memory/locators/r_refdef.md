---
title: r_refdef locator
type: note
permalink: goldsrc-vibesignatures/locators/r-refdef
tags:
  - locator
  - engine
  - gv
---

# r_refdef

## Symbol

- **Name**: `r_refdef`
- **Category**: `gv`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-r_refdef-ClientDLL_DrawNormalTriangles.py`
- **Source**: `engine/gl_rmain.c`; `R_RenderScene` opens with
  `if ( CL_IsDevOverviewMode() ) CL_SetDevOverView( &r_refdef );`

## Availability

- All 11 engine configs, every declared platform.

## Predecessors

- `CL_SetDevOverView` and `cl_funcs` (both declared as `expected_input`).

## How it is located

1. The **unique caller** of `CL_SetDevOverView` is the scene renderer. It is derived, never read
   from an `R_RenderScene` artifact, because svencoop-10257 Windows inlines `R_RenderScene` into
   `R_RenderView` and the call site lives there instead.
2. Within a 12-instruction window before each call site, the last `push`/`mov`/`lea` that names
   exactly one writable global and carries a four-byte displacement supplies the argument. Every
   call site must agree on one value.

Three compiler forms are covered: `push offset r_refdef` (MSVC),
`mov [esp], offset r_refdef` (GCC non-PIC) and `lea eax, (r_refdef - GOT)[ebx]` (GCC PIC).

## Pitfalls

- Keying the renderer on the name `R_RenderScene` fails on svencoop-10257 Windows (see above) and
  would also mis-key any future build that inlines differently.
- MetaHookSv's `Engine_FillAddress_RenderSceneVars` instead scans for `E8 ... 68 <refdef> ... 83`
  and reads the pushed immediate at `address-4`; that byte form does not exist on Linux.
- Validation evidence: hl-10210 W `0x10dc6320` / L `0xf7d8a0`, svencoop-8948 L `0x30d6ba0`.

## Relations

- relates_to [[CL_SetDevOverView]]
- relates_to [[ClientDLL_DrawNormalTriangles]]
