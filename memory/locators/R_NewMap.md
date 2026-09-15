---
title: R_NewMap locator
type: note
permalink: goldsrc-vibesignatures/locators/r-newmap
tags:
  - locator
  - engine
  - func
---

# R_NewMap

## Symbol

- **Name**: `R_NewMap`
- **Category**: `func`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**:
  - `ida_preprocessor_scripts/find-R_NewMap.py` (9 configs: cof-5936, hl-10210, hl-3248,
    hl-3266, hl-3329, hl-3647, hl-4554, hl-6153, hl-8684)
  - `ida_preprocessor_scripts/find-CL_RegisterResources-decompiles.py` (svencoop-10257 only)

## Availability

- Declared in 10 engine configs: cof-5936, hl-10210, hl-3248, hl-3266, hl-3329, hl-3647,
  hl-4554, hl-6153, hl-8684, svencoop-10257.
- Platforms: no `platform:` gating; only hl-10210, hl-8684 and svencoop-10257 declare
  `module_linux: hw.so`, the other seven configs are Windows-only here.
- Inlined / absent: always present. **The discovery anchor exists only in the non-Sven
  families** — SvEngine removed the `window02_1` texture literal.

## Predecessors

- None for `find-R_NewMap` (no `expected_input`, `old_yaml_map=None`).
- `CL_RegisterResources.{platform}.yaml` for the svencoop-10257 producer only, consumed via
  `expected_input` with the LLM dependency policy marked `"required"`. Reference
  disassembly: `references/{gamever}/engine/CL_RegisterResources.{platform}.yaml`.
- R_NewMap is itself the **required predecessor** of `find-R_NewMap-decompiles`
  (`r_worldentity`, `cl_worldmodel`, `GL_UnloadTextures`) in all 10 configs.

## How it is located

Two independent paths:

1. `find-R_NewMap` (HL / CoF families) — Pattern A string xref:
   `xref_strings: ["FULLMATCH:window02_1"]` (exact literal; the map reset searches
   sky/mirror textures after resetting lighting and world state). Exactly one function must
   survive; emit `func_name`, `func_sig`, `func_va`, `func_rva`, `func_size`.
2. `find-CL_RegisterResources-decompiles` (svencoop-10257) — `-decompiles` / LLM path with
   no literal of its own: load the required `CL_RegisterResources.{platform}.yaml`, export
   that function from the current IDB, prompt with `prompt/call_llm_decompile.md` and
   `expected_result_sections: ["found_call"]` against the annotated reference. The model must
   select the **renderer reset that follows resource/model registration**, not the
   `Hunk_Check` call that follows it (docstring). The shared consumer resolves the call
   target to a function entry and emits the function field set.

## Pitfalls

- The two producers are disjoint by config: svencoop-10257 does **not** register
  `find-R_NewMap`, and the other nine configs do **not** register
  `find-CL_RegisterResources-decompiles`. Do not add the Sven producer elsewhere.
- The Sven path needs a correct reference-driven model choice; the `window02_1` literal is
  absent there, so any attempt to reuse the HL anchor on SvEngine fails closed.
- Reference lookup falls back to the canonical gamever (`hl-10210`) when
  `references/{gamever}/engine/CL_RegisterResources.{platform}.yaml` is missing for the
  target tag; reference addresses are evidence only, never selectors.
- Downstream `find-R_NewMap-decompiles` requires this artifact and fails closed if it is
  missing or does not resolve in the current IDB.
- CoF (`cof-5936`) is Windows-only in this repo.
