---
title: GL_UnloadTextures locator
type: note
permalink: goldsrc-vibesignatures/locators/gl-unloadtextures
tags:
  - locator
  - engine
  - func
---

# GL_UnloadTextures

## Symbol

- **Name**: `GL_UnloadTextures`
- **Category**: `func`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-R_NewMap-decompiles.py`
  (emits `r_worldentity`, `cl_worldmodel` and `GL_UnloadTextures` from one run)

## Availability

- Declared in 10 engine configs: cof-5936, hl-10210, hl-3248, hl-3266, hl-3329, hl-3647,
  hl-4554, hl-6153, hl-8684, svencoop-10257.
- Platforms: no `platform:` gating; only hl-10210, hl-8684 and svencoop-10257 declare
  `module_linux: hw.so`, the other seven configs are Windows-only here.
- Inlined / absent: the map-reset body calls it (or tail-jumps to it on Linux), so the callee
  entry always exists, but its own body is a chain of small texture-slot loops — its
  in-function signature is not unique on some builds (see below).

## Predecessors

- `R_NewMap.{platform}.yaml` (produced by `find-R_NewMap` or, on svencoop-10257, by
  `find-CL_RegisterResources-decompiles`), consumed via `expected_input`; the LLM dependency
  policy marks it `"required"`.
- Reference disassembly: `references/{gamever}/engine/R_NewMap.{platform}.yaml`.

## How it is located

`-decompiles` (LLM) finder — no deterministic anchor of its own:

1. Load the required predecessor `R_NewMap.{platform}.yaml`, export that function from the
   current IDB, and prompt with `prompt/call_llm_decompile.md` and
   `expected_result_sections: ["found_call"]` against the annotated reference.
2. The docstring states R_NewMap drops every loaded GL texture through `GL_UnloadTextures`
   before rebuilding the lightmaps; the model must select that call. The shared consumer
   resolves the call target (or the Linux tail jump) to the **full function entry** and emits
   `func_name`, `func_sig`, `func_va`, `func_rva`, `func_size`.
3. The desired-field list for this symbol additionally carries
   `func_sig_allow_across_function_boundary:true`, which lifts the signature caps
   (fixed → 256, tokens → 256) so the wildcarded signature can grow until unique across the
   adjacent unload helpers.

## Pitfalls

- `func_sig_allow_across_function_boundary:true` is **required** here, not cosmetic: the
  in-function window mirrors the neighbouring unload helpers on several builds, so only an
  across-boundary window stays unique. The flag is set in the finder's
  `generate_yaml_desired_fields`, never in the config symbol.
- A Linux tail jump must still resolve to the real entry; do not accept an address adjacent to
  the call target.
- Discovery never reuses this symbol's pre-existing artifact (`old_yaml_map=None`); the only
  consumed artifact is the required R_NewMap predecessor.
- Reference lookup falls back to the canonical gamever (`hl-10210`) when the per-gamever
  reference file is missing; reference addresses are evidence only, never selectors.
- CoF (`cof-5936`) is Windows-only in this repo.
