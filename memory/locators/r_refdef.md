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
2. Recover the first stack argument at each call site within its basic block, using IDA's stack
   deltas and the shared `x86_call_arguments` backward tracer. Follow immediate address loads,
   register copies and PIC `lea` definitions to the instruction encoding the address. Every call
   site must resolve successfully and agree on one value. Unknown overwrites, intervening calls
   and definitions outside the basic block are rejected.

Three compiler forms are covered: `push offset r_refdef` (MSVC),
`mov [esp], offset r_refdef` (GCC non-PIC) and `lea eax, (r_refdef - GOT)[ebx]` (GCC PIC).

## Pitfalls

- Keying the renderer on the name `R_RenderScene` fails on svencoop-10257 Windows (see above) and
  would also mis-key any future build that inlines differently.
- MetaHookSv's `Engine_FillAddress_RenderSceneVars` instead scans for `E8 ... 68 <refdef> ... 83`
  and reads the pushed immediate at `address-4`; that byte form does not exist on Linux.
- A nearby global reference is not proof of an argument: `push offset r_refdef; mov eax, [other];
  call CL_SetDevOverView` must retain the pushed address. The former nearest-reference heuristic
  incorrectly selected `other`. Regressions in `tests/test_x86_call_arguments.py` exercise the
  actual locator walk for this case, compiler argument forms, overwritten arguments and basic
  block boundaries. This constraint applies to locators deriving globals from call arguments.
- Validation evidence: hl-10210 W `0x10dc6320` / L `0xf7d8a0`, svencoop-8948 L `0x30d6ba0`.

## Relations

- relates_to [[CL_SetDevOverView]]
- relates_to [[ClientDLL_DrawNormalTriangles]]
