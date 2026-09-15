---
title: R_StudioMergeBones locator
type: note
permalink: goldsrc-vibesignatures/locators/r-studiomergebones
tags:
  - locator
  - engine
  - func
---

# R_StudioMergeBones

## Symbol

- **Name**: `R_StudioMergeBones`
- **Category**: `func`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-R_StudioDrawPlayerBody-decompiles.py`

## Availability

- Declared in 10 configs: cof-5936, hl-10210, hl-3248, hl-3266, hl-3329, hl-3647,
  hl-4554, hl-6153, hl-8684, svencoop-10257.
- Platforms: Windows + Linux (no `platform:` gating).
- Inlined / absent: `R_StudioMergeBones` has no unique literal of its own, so the finder
  is a `-decompiles` (LLM) variant. It exists as a separate weapon-model merge routine on
  every family; nothing suggests it is folded into the caller as a distinct symbol.

## Predecessors

- `R_StudioDrawPlayerBody.{platform}.yaml` (produced by `find-R_StudioDrawPlayer-body`,
  consumed via `expected_input`; declared `"required"` in the LLM dependency policy).
- Reference disassembly for the LLM step:
  `references/{gamever}/engine/R_StudioDrawPlayerBody.{platform}.yaml`.

## How it is located

This is a pure `preprocess_common_skill` *LLM_DECOMPILE* finder — there is no deterministic
anchor chain of its own:

1. Load the required predecessor `R_StudioDrawPlayerBody.{platform}.yaml`.
2. Run the shared LLM-decompile contract with `prompt/call_llm_decompile.md`, the
   canonical reference YAML above, and `expected_result_sections: ["found_call"]`. The
   model selects the direct call inside the player's rendering body that is
   `R_StudioMergeBones` (the weapon-model bone merge), and the shared consumer resolves the
   selected instruction back to a code target.
3. Emit `func_name`/`func_va`/`func_rva`/`func_size`/`func_sig` plus
   `func_sig_allow_across_function_boundary: true` (requested unconditionally in the
   desired-fields list).
4. `old_yaml_map=None`: discovery never consumes a previous artifact signature.

## Pitfalls

- The predecessor is mandatory; a missing or stale `R_StudioDrawPlayerBody` artifact stops
  the finder before any LLM call.
- The anchor is a *call instruction* inside a large body: the LLM must return the merge
  call, not the nearest `R_StudioSetupBones`/`R_StudioCalcAttachments` or a bone-cache
  access. Addresses in the reference YAML are evidence, never selectors.
- The `allow_across_function_boundary` flag is always emitted, so a wildcarded tail is
  acceptable in the signature.
- Do not confuse this with `R_StudioSaveBones`, which writes the same cache; the merge
  routine *reads* it.

## Evidence

- Reference disassembly exists for hl-10210, hl-3248, hl-6153, hl-8684, cof-5936 and
  svencoop-10257 (both platforms where shipped) under
  `ida_preprocessor_scripts/references/{gamever}/engine/R_StudioMergeBones.{platform}.yaml`,
  which is also the LLM predecessor for the `cached_numbones` / `cached_bonename` finder.
