---
title: r_worldentity locator
type: note
permalink: goldsrc-vibesignatures/locators/r-worldentity
tags:
  - locator
  - engine
  - gv
---

# r_worldentity

## Symbol

- **Name**: `r_worldentity`
- **Category**: `gv`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-R_NewMap-decompiles.py`
  (emits `r_worldentity`, `cl_worldmodel` and `GL_UnloadTextures` from one run)

## Availability

- Declared in 10 engine configs: cof-5936, hl-10210, hl-3248, hl-3266, hl-3329, hl-3647,
  hl-4554, hl-6153, hl-8684, svencoop-10257.
- Platforms: no `platform:` gating; only hl-10210, hl-8684 and svencoop-10257 declare
  `module_linux: hw.so`, the other seven configs are Windows-only here.
- Inlined / absent: it is a file-scope engine object; always present. The *access form*
  differs (absolute operand on Windows, PIC/GOTOFF on SvEngine Linux).

## Predecessors

- `R_NewMap.{platform}.yaml` (produced by `find-R_NewMap` or, on svencoop-10257, by
  `find-CL_RegisterResources-decompiles`), consumed via `expected_input`; the LLM dependency
  policy marks it `"required"`.
- Reference disassembly: `references/{gamever}/engine/R_NewMap.{platform}.yaml`.

## How it is located

`-decompiles` (LLM) finder — no deterministic anchor of its own:

1. Load the required predecessor `R_NewMap.{platform}.yaml` and export that function from the
   current IDB (comments stripped; annotated reference supplied separately).
2. Run the shared LLM-decompile contract (`prompt/call_llm_decompile.md`) with
   `expected_result_sections: ["found_gv"]`. The model picks the global access that is
   `r_worldentity`; the shared consumer resolves the operand to an address and re-checks the
   live instruction, target-function membership, displacement/size and pointer size.
3. Emit `gv_name`, `gv_va`, `gv_rva`, `gv_sig`, `gv_sig_va`, `gv_inst_offset`,
   `gv_inst_length`, `gv_inst_disp` (plus `gv_pic_addend` on PIC Linux).

## Pitfalls

- **Whole-object memset vs model member.** R_NewMap clears the complete `r_worldentity`
  object, while `R_RenderView`'s access to its model member encodes a *field* address instead
  of the entity base. This is a real candidate-selection risk, not an observed failure: the
  finder must pin the anchor to the memset/whole-object access in the R_NewMap body.
- The finder never reuses its own same-named pre-existing artifact for discovery
  (`old_yaml_map=None`); the only artifact it consumes is the predecessor above, which must
  exist and be valid in the current IDB or the run fails closed.
- Reference lookup falls back to the canonical gamever (`hl-10210`) when the per-gamever
  reference file is missing; reference addresses are evidence only, never selectors.
- On SvEngine Linux the operand is PIC/GOTOFF — resolve `gv_inst_disp` against
  `gv_pic_addend` (same contract as `cl_parsefuncs` and `cl_resourcesonhand`), never by
  treating the embedded dword as an absolute VA.
- CoF (`cof-5936`) is Windows-only in this repo.
