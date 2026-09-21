---
title: R_StudioSetupLighting locator
type: note
permalink: goldsrc-vibesignatures/locators/r-studiosetuplighting
tags:
  - locator
  - engine
  - func
---

# R_StudioSetupLighting

## Symbol

- **Name**: `R_StudioSetupLighting`
- **Category**: `func` plus globals `r_ambientlight` (`gv`, int), `r_shadelight` (`gv`, float), `r_colormix` (`gv`, vec3)
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-R_StudioSetupLighting.py`
  (shared `ida_preprocessor_scripts._studio_setup_common.preprocess_studio_setup_lighting`)

## Availability

- Declared in 11 engine configs: hl-3248, hl-3266, hl-3329, hl-3647, hl-4554, hl-6153,
  hl-8684, hl-10210, cof-5936, svencoop-8948, svencoop-10257.
- Platforms: Windows + Linux (no `platform:` gating). The finder tries both HL and
  SvEngine ClientDLL_CheckStudioInterface diagnostics, so one script covers every family.
- Inlined / absent: never inlined — it is `engine_studio_api_t` slot 24 (`0x60`).

## Predecessors

- None. The engine studio API table is re-derived from the interface diagnostic each run.

## How it is located

1. For each diagnostic in `(HL_STUDIO_STRING, SVC_STUDIO_STRING)`, call
   `locate_studio_slot(..., 24 * 4)` and require exactly one distinct `slot_va`.
2. Materialize the function at that slot (`_inspect_function_via_mcp`, across-boundary
   fallback if the strict window is not unique).
3. Recover the three globals from the slot body with a current-IDB operand walk:
   - `r_ambientlight`: unique int store of `plighting->ambientlight` (`alight_t+0`).
   - `r_shadelight`: unique float store of the int-to-float conversion of
     `plighting->shadelight` (`alight_t+4`, `fild` / `movd`+`cvtdq2ps`).
   - `r_colormix`: unique 12-byte consecutive float-store cluster after the first
     `AND …, 0xFF00` (`r_icolormix` packing). Integer `A3` stores of that AND are ignored.
4. `plighting` is the unique incoming pointer used both as a disp-0 dword load and as a
   disp-4 integer-to-float source, including reloads from the same `[ebp+8]` / `[esp+N]`
   slot. `r_plightvec` / `r_blightvec` / `r_icolormix` are not emitted.

## Pitfalls

- Slot 24 is the real `R_StudioSetupLighting`, not a wrapper.
- Do not pick `r_plightvec` (dword copies through `alight_t.plightvec` at +0x14) or
  `r_icolormix` (int stores of `* 0xC0FF & 0xFF00`).
- Do not sort globals by VA: `r_ambientlight` and `r_shadelight` are adjacent on some
  builds and far apart on others.
- SvEngine Linux stores are GOTOFF (`gv_pic_addend`).
