---
title: R_StudioRenderModel locator
type: note
permalink: goldsrc-vibesignatures/locators/r-studiorendermodel
tags:
  - locator
  - engine
  - func
---

# R_StudioRenderModel

## Symbol

- **Name**: `R_StudioRenderModel`
- **Category**: `func`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-R_StudioRenderModel.py`
  (via `preprocess_common_skill` + `func_xrefs`)

## Availability

- Declared in 10 configs: cof-5936, hl-10210, hl-3248, hl-3266, hl-3329, hl-3647,
  hl-4554, hl-6153, hl-8684, svencoop-10257.
- Platforms: Windows + Linux (no `platform:` gating).
- Inlined / absent: the standalone renderer still ships everywhere; compilers **also**
  inline it into the top-level DrawModel/DrawPlayer paths, whose copies are the reason for
  the exclusion set below.

## Predecessors

All six are consumed via `expected_input`:

- `cl_sprite_shell.{platform}.yaml`, `g_ChromeOrigin.{platform}.yaml` — the two intersected
  globals
- `R_StudioDrawModel.{platform}.yaml`, `R_StudioDrawPlayer.{platform}.yaml` — exclusion
  (`exclude_funcs`)
- `R_StudioSetupBones.{platform}.yaml`, `R_StudioCalcAttachments.{platform}.yaml` —
  exclusion (`exclude_callees`)

## How it is located

1. The `func_xrefs` entry declares `xref_gvs: ["cl_sprite_shell", "g_ChromeOrigin"]` and no
   strings/signatures/functions: the candidate is the function that intersects the two
   chrome globals. The standalone renderer is the pass that resets chrome state and renders
   the glowshell pass, so it touches both.
2. Exclusion by source role:
   - `exclude_funcs: ["R_StudioDrawModel", "R_StudioDrawPlayer"]` — the top-level draw paths
     that inlined the same globals;
   - `exclude_callees: ["R_StudioSetupBones", "R_StudioCalcAttachments"]` — any function
     that calls the bone-setup / attachment routines belongs to those inlining paths, not
     to the standalone renderer.
3. Classic signature path first, GV-intersection xref as fallback; `old_yaml_map=None`.
4. Emits `func_name`/`func_va`/`func_rva`/`func_size`/`func_sig` plus
   `func_sig_allow_across_function_boundary: true` (requested unconditionally).

## Pitfalls

- A bare `cl_sprite_shell` xref is not enough: both globals must be owned by the same
  function, and the inlining draw wrappers own them too. Without the exclusion set the
  locator is ambiguous.
- The GV predecessors are the anchor inputs; if `cl_sprite_shell` or `g_ChromeOrigin` is
  mislocated, this symbol is mislocated too.
- The across-boundary signature flag is always emitted, so a wildcarded entry tail is
  acceptable.
- Discovery never consumes an old artifact signature.

## Evidence

- Reference disassembly exists for hl-10210, hl-3248, hl-6153, hl-8684, cof-5936 and
  svencoop-10257 (both platforms where shipped) under
  `ida_preprocessor_scripts/references/{gamever}/engine/R_StudioRenderModel.{platform}.yaml`,
  which is the LLM predecessor for `find-R_StudioRenderModel-decompiles`.
- Issue #106 records the static different-target risk for this family: the CoF
  shell-sprite/chrome intersection is one of the candidate-selection risks flagged in the
  BulletPhysics locator note.
