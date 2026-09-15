---
title: R_CullBox locator
type: note
permalink: goldsrc-vibesignatures/locators/r-cullbox
tags:
  - locator
  - engine
  - func
---

# R_CullBox

## Symbol

- **Name**: `R_CullBox`
- **Category**: `func`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-R_StudioCheckBBox-decompiles.py`

## Availability

- Declared in 10 configs: cof-5936, hl-10210, hl-3248, hl-3266, hl-3329, hl-3647,
  hl-4554, hl-6153, hl-8684, svencoop-10257.
- Platforms: Windows + Linux (no `platform:` gating).
- Inlined / absent: `R_CullBox` has no literal of its own, so the finder is the
  `-decompiles` (LLM) variant. It is a shared culler used outside the Studio path too, so
  it exists as a real function on every build; nothing suggests it is fully folded away.

## Predecessors

- `R_StudioCheckBBox.{platform}.yaml` (produced by `find-R_StudioCheckBBox`, consumed via
  `expected_input`; declared `"required"` in the LLM dependency policy).
- Reference disassembly: `references/{gamever}/engine/R_StudioCheckBBox.{platform}.yaml`.

## How it is located

Pure LLM_DECOMPILE finder (no deterministic anchor of its own):

1. Load the required predecessor `R_StudioCheckBBox.{platform}.yaml`.
2. Run the shared LLM-decompile contract (`prompt/call_llm_decompile.md`) with
   `expected_result_sections: ["found_call"]`: the model selects the **shared
   four-frustum-plane box culler** called from the `R_StudioCheckBBox` body, and the shared
   consumer resolves the selected call instruction to a function target.
3. Emit `func_name`/`func_va`/`func_rva`/`func_size`/`func_sig`. Unlike the other
   `-decompiles` funcs in this family, **no** across-boundary flag is requested.
4. `old_yaml_map=None`: no prior artifact signature drives discovery.

## Pitfalls

- `R_StudioCheckBBox` is a small wrapper around the culler; the model must pick the
  four-plane culler call, not a neighbouring plane-test helper.
- This symbol is a *shared* culler — it is reachable from many non-Studio paths, so the
  same-target/different-anchor risk applies. Selection must stay scoped to the verified
  `R_StudioCheckBBox` body (the DAG predecessor), never to a global xref scan.
- The predecessor is mandatory; a missing `R_StudioCheckBBox` artifact fails closed.
- Addresses in the reference YAML are evidence, never selectors.
- Unlike the other LLM func outputs in this batch, this one does **not** set
  `func_sig_allow_across_function_boundary`, so the emitted signature must be unique within
  the strict window.

## Evidence

- Reference disassembly exists for hl-10210, hl-3248, hl-6153, hl-8684, cof-5936 and
  svencoop-10257 (both platforms where shipped) under
  `ida_preprocessor_scripts/references/{gamever}/engine/R_StudioCheckBBox.{platform}.yaml`.
