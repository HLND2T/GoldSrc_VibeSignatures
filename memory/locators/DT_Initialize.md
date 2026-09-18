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

- Declared in 7 engine configs: cof-5936, hl-10210, hl-4554, hl-6153, hl-8684,
  svencoop-8948, svencoop-10257.
- Platforms: Windows + Linux.
- Branch split on svencoop-8948 / svencoop-10257: Windows is emitted by
  `find-renderer-draw-helpers-svencoop` (`platform: windows`), Linux by
  `find-DT_Initialize-svencoop` (`platform: linux`). The 5 HL/CoF configs use
  `find-renderer-draw-helpers` (no platform gating).
- **Inlined on the BLOB builds** (`hl-3248` / `hl-3266` / `hl-3329` / `hl-3647`):
  `DT_Initialize` has no standalone body there — it is inlined into
  `CheckMultiTextureExtensions` (`engine/gl_vidnt.c`). Those four configs therefore
  **must not declare the symbol**; the registration and the four
  `bin_artifacts/hl-<tag>/engine/DT_Initialize.windows.yaml` files were removed
  (2026-09-18) because they recorded the host function, not `DT_Initialize`.
  The host is now a first-class symbol produced by `find-CheckMultiTextureExtensions`.
- Everywhere else `engine/DetailTexture.cpp DT_Initialize` stays a standalone
  function, including SvEngine Linux — unlike the sprite-frame renderers, which are
  inlined there.

### Evidence for the BLOB inlining

Read straight out of `bin/<tag>/engine/hw.decrypt.dll` at the recorded RVA:

- The four removed artifacts were byte-identical in shape — `func_size 0x18d`,
  `func_sig` opening `51 D9 05 ?? ?? ?? ?? D8 1D ?? ?? ?? ?? DF E0 F6 C4 44 0F 8A`
  (an FPU compare, not the two `Cvar_RegisterVariable` pushes of the real function).
- Their bodies push `GL_ARB_multitexture `, `ARB Multitexture extensions found.\n`,
  `glMultiTexCoord2fARB`, `glActiveTextureARB`, `GL_SGIS_multitexture `,
  `NO Multitexture extensions found.\n` **and** the inlined detail-texture line
  `%d texture units.  Detail texture supported.\n` — i.e. the whole
  `CheckMultiTextureExtensions` body.
- The 7 kept Windows artifacts are `0x8d`-`0x95` bytes and register the
  `r_detailtextures` / `r_detailtexturessupported` cvars, which is the genuine
  `DT_Initialize`.

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
5. `find-renderer-draw-helpers` skips `DT_WALK` entirely when the config does not list
   `DT_Initialize.{platform}.yaml` in `expected_output`; the other four draw helpers it
   produces are unaffected, which is what keeps the BLOB configs working.

## Pitfalls

- The anchor is an `o_imm` operand, so a build that materializes `GL_RGB_SCALE` through a
  computed or register-relative value would not match; there is no secondary anchor.
- Uniqueness is mandatory — the walk has no recovery path if two functions push `0x8573`.
- **Uniqueness is not a correctness proof.** The `0x8573` immediate survives inlining, so
  on the BLOB builds the walk returned exactly one hit and looked healthy while pointing at
  `CheckMultiTextureExtensions`. Before declaring the symbol for a new build, check that the
  hit is `DT_Initialize`-sized (`0x8d`-`0x95`) and registers `r_detailtextures` /
  `r_detailtexturessupported`; a `0x18d`-byte hit full of `*_multitexture` strings is the
  host function.
- Prior float/immediate matching work (issue #114) noted that SvEngine Linux hides
  `.rodata` operands behind GOT-relative displacements for *float* constants; `0x8573` is
  a plain integer immediate here and is unaffected, but the same PIC reasoning explains
  why the walk must use decoded `o_imm` rather than byte-scanning for the constant.
