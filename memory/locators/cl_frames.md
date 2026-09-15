---
title: cl_frames locator
type: note
permalink: goldsrc-vibesignatures/locators/cl-frames
tags:
  - locator
  - engine
  - gv
---

# cl_frames

## Symbol

- **Name**: `cl_frames`
- **Category**: `gv`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-CL_ReallocateDynamicData-decompiles.py`
  (emits `cl_max_edicts`, `cl_entities` and `cl_frames` from one run)

## Availability

- Declared in 10 engine configs: cof-5936, hl-10210, hl-3248, hl-3266, hl-3329, hl-3647,
  hl-4554, hl-6153, hl-8684, svencoop-10257.
- Platforms: no `platform:` gating; only hl-10210, hl-8684 and svencoop-10257 declare
  `module_linux: hw.so`, the other seven configs are Windows-only here.
- Inlined / absent: it is the client frame-ring array base published by
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
2. The finder docstring states the selection constraint explicitly: "The frame-ring memset
   owns the array base, unlike render accesses that may encode a playerstate member address
   within each frame." The model must pick the memset/array-base access, and the shared
   consumer resolves it and emits the GV field set (`gv_name`, `gv_va`, `gv_rva`, `gv_sig`,
   `gv_sig_va`, `gv_inst_offset`, `gv_inst_length`, `gv_inst_disp`, plus `gv_pic_addend`).

## Pitfalls

- **Interior-member trap:** a frame *member* address (e.g. a playerstate field inside one
  frame) is a plausible-looking but wrong leaf; only the memset that owns the ring base is
  correct. This is the documented reason the anchor function is the allocator rather than a
  render function.
- **Same-target / different-anchor risk** applies (multiple legitimate accesses); the emitted
  anchor can move between runs if selection is not pinned to the verified body. Do not accept
  a bare xref scan as discovery.
- Discovery never reuses this symbol's own pre-existing artifact (`old_yaml_map=None`).
- Reference lookup falls back to the canonical gamever (`hl-10210`) when the per-gamever
  reference file is missing; reference addresses are evidence only, never selectors.
- On SvEngine Linux resolve the PIC addend (`gv_pic_addend`).
- CoF (`cof-5936`) is Windows-only in this repo.
