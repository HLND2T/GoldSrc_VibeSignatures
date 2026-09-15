---
title: cl_entities locator
type: note
permalink: goldsrc-vibesignatures/locators/cl-entities
tags:
  - locator
  - engine
  - gv
---

# cl_entities

## Symbol

- **Name**: `cl_entities`
- **Category**: `gv`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-CL_ReallocateDynamicData-decompiles.py`
  (emits `cl_max_edicts`, `cl_entities` and `cl_frames` from one run)

## Availability

- Declared in 10 engine configs: cof-5936, hl-10210, hl-3248, hl-3266, hl-3329, hl-3647,
  hl-4554, hl-6153, hl-8684, svencoop-10257.
- Platforms: no `platform:` gating; only hl-10210, hl-8684 and svencoop-10257 declare
  `module_linux: hw.so`, the other seven configs are Windows-only here.
- Inlined / absent: it is the dynamically reallocated client entity array base, owned by
  `CL_ReallocateDynamicData`; always present. The *access form* differs (absolute operand on
  Windows, PIC/GOTOFF on SvEngine Linux).

## Predecessors

- `CL_ReallocateDynamicData.{platform}.yaml` (produced by `find-CL_ReallocateDynamicData`),
  consumed via `expected_input`; the LLM dependency policy marks it `"required"`.
- Reference disassembly:
  `references/{gamever}/engine/CL_ReallocateDynamicData.{platform}.yaml`.

## How it is located

`-decompiles` (LLM) finder — no deterministic anchor of its own:

1. Load the required predecessor `CL_ReallocateDynamicData.{platform}.yaml`, export that
   function from the current IDB, and prompt with `prompt/call_llm_decompile.md` and
   `expected_result_sections: ["found_gv"]` against the annotated reference.
2. The model picks the global access that is `cl_entities`; the shared consumer resolves the
   operand, re-checks the live instruction and unique target, and emits the GV field set
   (`gv_name`, `gv_va`, `gv_rva`, `gv_sig`, `gv_sig_va`, `gv_inst_offset`,
   `gv_inst_length`, `gv_inst_disp`, plus `gv_pic_addend` where PIC).

## Pitfalls

- **Same-target / different-anchor risk** (shared with `cl_frames`, `cl_max_edicts`,
  `mod_known`, `mod_numknown`, `cl_worldmodel`): the symbol has multiple legitimate accesses,
  so the emitted `gv_inst_offset`/anchor can change with a different (still valid) access.
  Selection is pinned to the verified allocator body.
- Discovery never reuses this symbol's own pre-existing artifact (`old_yaml_map=None`); the
  only consumed artifact is the required allocator predecessor.
- Reference lookup falls back to the canonical gamever (`hl-10210`) when the per-gamever
  reference file is missing; reference addresses are evidence only, never selectors.
- On SvEngine Linux resolve the PIC addend (`gv_pic_addend`) instead of reading the embedded
  dword as an absolute VA.
- CoF (`cof-5936`) is Windows-only in this repo.
