---
title: DT_Initialize locator
type: note
permalink: goldsrc-vibesignatures/locators/dt-initialize
tags:
  - locator
  - engine
  - func
---

# DT_Initialize

## Symbol

- **Name**: `DT_Initialize`
- **Category**: `func`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-renderer-draw-helpers.py`,
  `ida_preprocessor_scripts/find-renderer-draw-helpers-svencoop.py`,
  `ida_preprocessor_scripts/find-DT_Initialize-svencoop.py`

## Availability

- Declared in 10 engine configs: cof-5936, hl-10210, hl-3248, hl-3266, hl-3329,
  hl-3647, hl-4554, hl-6153, hl-8684, svencoop-10257.
- Platforms: Windows + Linux.
- Branch split on svencoop-10257: Windows is emitted by `find-renderer-draw-helpers-svencoop`
  (`platform: windows`), Linux by `find-DT_Initialize-svencoop` (`platform: linux`).
  The 9 HL/CoF configs use `find-renderer-draw-helpers` (no platform gating).
- Inlined / absent: none observed. `engine/DetailTexture.cpp DT_Initialize` stays a
  standalone function on every validated branch, including SvEngine Linux — unlike the
  sprite-frame renderers, which are inlined there.

## Predecessors

- `<nothing required by the walk>`. The HL/CoF producer loads
  `SCR_UpdateScreen_RenderBody`, `Sys_Error` and `cl_enginefuncs` artifacts as an entry
  gate (`expected_input`), but the `DT_Initialize` walk itself consumes none of them.
- `find-DT_Initialize-svencoop` and `find-renderer-draw-helpers-svencoop` declare no inputs.

## How it is located

1. Enumerate every `idautils.Functions()` entry and decode its instructions; keep the
   functions whose body carries an **immediate operand equal to `GL_RGB_SCALE` (0x8573)**.
   Only `o_imm` operands count — a value merely loaded from memory does not match.
2. Require exactly one hit. Zero or several hits emit `DT_Initialize_candidates` and the
   run fails closed (nothing is written).
3. `_inspect_function_via_mcp` then produces `func_va` / `func_rva` / `func_size` /
   `func_sig` and re-verifies the signature is unique in the binary; on failure the inspect
   is retried with `allow_across_function_boundary=True` and the payload is flagged.
4. The three producers run the identical `DT_WALK`; they differ only in entry gating
   (`find-renderer-draw-helpers` additionally requires the SCR/Sys_Error/cl_enginefuncs
   YAMLs to exist and carry `func_va` / `gv_va`). No byte pattern participates in discovery.

## Pitfalls

- The anchor is an `o_imm` operand, so a build that materializes `GL_RGB_SCALE` through a
  computed or register-relative value would not match; there is no secondary anchor.
- Uniqueness is mandatory — the walk has no recovery path if two functions push `0x8573`.
- Prior float/immediate matching work (issue #114) noted that SvEngine Linux hides
  `.rodata` operands behind GOT-relative displacements for *float* constants; `0x8573` is
  a plain integer immediate here and is unaffected, but the same PIC reasoning explains
  why the walk must use decoded `o_imm` rather than byte-scanning for the constant.
