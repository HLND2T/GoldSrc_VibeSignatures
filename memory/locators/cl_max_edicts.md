---
title: cl_max_edicts locator
type: note
permalink: goldsrc-vibesignatures/locators/cl-max-edicts
tags:
  - locator
  - engine
  - gv
---

# cl_max_edicts

## Symbol

- **Name**: `cl_max_edicts`
- **Category**: `gv`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-CL_ReallocateDynamicData-decompiles.py`
  (emits `cl_max_edicts`, `cl_entities` and `cl_frames` from one run)

## Availability

- Declared in 10 engine configs: cof-5936, hl-10210, hl-3248, hl-3266, hl-3329, hl-3647,
  hl-4554, hl-6153, hl-8684, svencoop-10257.
- Platforms: no `platform:` gating; only hl-10210, hl-8684 and svencoop-10257 declare
  `module_linux: hw.so`, the other seven configs are Windows-only here.
- Inlined / absent: it is the edict-capacity scalar written by the allocator; always present.
  The *access form* differs (absolute operand on Windows, PIC/GOTOFF on SvEngine Linux).

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
2. The model picks the global access that is `cl_max_edicts` (the reallocated maximum edict
   count) inside the allocator body; the shared consumer resolves the operand and re-checks
   the live instruction before emitting the GV field set (`gv_name`, `gv_va`, `gv_rva`,
   `gv_sig`, `gv_sig_va`, `gv_inst_offset`, `gv_inst_length`, `gv_inst_disp`, plus
   `gv_pic_addend` where PIC).

## Pitfalls

- **Same-target / different-anchor risk**: the edict-count scalar is read in several places,
  so a different (still valid) access changes the emitted anchor. Selection is pinned to the
  verified allocator body instead of a bare xref scan.
- The symbol is a count/limit, not the entity array: do not accept `cl_entities`'s address in
  its place (the two are emitted together from the same run and must stay distinct).
- Discovery never reuses this symbol's own pre-existing artifact (`old_yaml_map=None`).
- Reference lookup falls back to the canonical gamever (`hl-10210`) when the per-gamever
  reference file is missing; reference addresses are evidence only, never selectors.
- On SvEngine Linux resolve the PIC addend (`gv_pic_addend`).
- CoF (`cof-5936`) is Windows-only in this repo.
