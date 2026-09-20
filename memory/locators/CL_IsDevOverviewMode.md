---
title: CL_IsDevOverviewMode locator
type: note
permalink: goldsrc-vibesignatures/locators/cl-isdevoverviewmode
tags:
  - locator
  - engine
  - func
---

# CL_IsDevOverviewMode

## Symbol

- **Name**: `CL_IsDevOverviewMode`
- **Category**: `func`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-CL_IsDevOverviewMode.py`
- **Source**: `engine/cl_spectator.c`, the predicate that gates the development
  overview camera. Confirmed by the retained `.symtab` of hl-10210, hl-8684 and
  svencoop-8948 `hw.so`.

## Availability

- All 11 engine configs, every declared platform. BLOB tags analyse
  `hw.decrypt.dll`.

## Predecessors

- `CL_SetDevOverView.{platform}.yaml`.

## How it is located

`engine/gl_rmain.c`:

    if ( CL_IsDevOverviewMode() )
        CL_SetDevOverView( &r_refdef );

so the target is the nearest call before a `CL_SetDevOverView` call site. The
renderer is derived, never named — it is the unique caller of `CL_SetDevOverView`
— because SvEngine 10257 Windows inlines `R_RenderScene` into `R_RenderView` and
the older builds put unrelated calls first.

The call may sit in the same basic block as the setter call (CoF, SvEngine
Windows) or in the guard block that branches into the setter block (HL25 Linux),
so the search walks backwards across single-predecessor blocks. The candidate
must stay under `0x80` bytes and make at most one call, which excludes
`CL_CalculateDevOverviewParameters`.

## Pitfalls

- "The renderer's first call" is wrong: cof-5936 calls `Cvar_DirectSet` first and
  svencoop-10257 Windows calls `Sys_Error` first.
- On macOS-style lazy PLT builds the guard call is routed through a `.plt` stub;
  the walk resolves it with `resolve_elf_plt` rather than requiring a direct
  callee.
- SvEngine's version is not a leaf — it resolves the `dev_overview` cvar through
  a helper — so a leaf-only filter rejects the correct candidate.
- Validation evidence: hl-10210 W `0x101ad020` / L `0x12d560`,
  hl-8684 L `0x185200`, cof-5936 `0x1d3bc6d`, svencoop-8948 W `0x1d038a0` /
  L `0x1558e0`, svencoop-10257 W `0x1d03870` / L `0x108d60`.

## Relations

- relates_to [[CL_SetDevOverView]]
- relates_to [[r_refdef]]
