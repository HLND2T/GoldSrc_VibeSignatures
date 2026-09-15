---
title: R_StudioRenderFinal locator
type: note
permalink: goldsrc-vibesignatures/locators/r-studiorenderfinal
tags:
  - locator
  - engine
  - func
---

# R_StudioRenderFinal

## Symbol

- **Name**: `R_StudioRenderFinal`
- **Category**: `func`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-R_StudioRenderModel-decompiles.py`

## Availability

- Declared in 10 configs: cof-5936, hl-10210, hl-3248, hl-3266, hl-3329, hl-3647,
  hl-4554, hl-6153, hl-8684, svencoop-10257.
- Platforms: Windows + Linux (no `platform:` gating).
- Inlined / absent: `R_StudioRenderFinal` has no literal of its own, so the finder is the
  `-decompiles` (LLM) variant. Note the HL-family Linux split: the full
  `R_StudioRenderModel` entry and its **inlined** hardware/software children are *distinct*
  vtable slots — the correct one is the full entry, not a child.

## Predecessors

- `R_StudioRenderModel.{platform}.yaml` (produced by `find-R_StudioRenderModel`, consumed
  via `expected_input`; declared `"required"` in the LLM dependency policy).
- Reference disassembly: `references/{gamever}/engine/R_StudioRenderModel.{platform}.yaml`.

## How it is located

Pure LLM_DECOMPILE finder (no deterministic anchor of its own):

1. Load the required predecessor `R_StudioRenderModel.{platform}.yaml`.
2. Run the shared LLM-decompile contract (`prompt/call_llm_decompile.md`) with
   `expected_result_sections: ["found_call"]`: the model selects the final studio pass
   called before the glowshell sprite setup, and the shared consumer resolves the selected
   call instruction to a function target.
3. Emit `func_name`/`func_va`/`func_rva`/`func_size`/`func_sig` plus
   `func_sig_allow_across_function_boundary: true` (requested unconditionally).
4. `old_yaml_map=None`: no prior artifact signature is used for discovery.

## Pitfalls

- **HL-family Linux vtable split**: the full `R_StudioRenderModel` entry and its inlined
  hardware/software children are distinct vtable slots. Accepting a mislabelled child
  `found_vcall` before the correct `found_funcptr` produces the wrong function — the
  selection must land on the full entry. (Repeated direct calls to the same function
  generally produce identical function artifacts and are benign.)
- The predecessor is mandatory; a missing `R_StudioRenderModel` artifact fails closed.
- Addresses in the reference YAML are evidence, never selectors.
- The across-boundary signature flag is always emitted.

## Evidence

- Reference disassembly exists for hl-10210, hl-3248, hl-6153, hl-8684, cof-5936 and
  svencoop-10257 (both platforms where shipped) under
  `ida_preprocessor_scripts/references/{gamever}/engine/R_StudioRenderModel.{platform}.yaml`.
- The vtable-slot split risk is recorded in the BulletPhysics private symbol locators note
  ("Non-GV risk").
