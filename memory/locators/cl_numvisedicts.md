---
title: cl_numvisedicts locator
type: note
permalink: goldsrc-vibesignatures/locators/cl-numvisedicts
tags:
  - locator
  - engine
  - gv
---

# cl_numvisedicts

## Symbol

- **Name**: `cl_numvisedicts`
- **Category**: `gv`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-CL_CreateVisibleEntity-decompiles.py`

## Availability

- Declared in 10 engine configs: cof-5936, hl-10210, hl-3248, hl-3266, hl-3329, hl-3647, hl-4554, hl-6153, hl-8684, svencoop-10257.
- Platforms: Windows + Linux.
- Inlined / absent: none observed.

## Predecessors

- `CL_CreateVisibleEntity` (produced by `find-CL_CreateVisibleEntity`, consumed via `expected_input` and `dependency_policy: required`).

## How it is located

1. Requires the current `CL_CreateVisibleEntity.{platform}.yaml`; returns `False` without it.
2. `LLM_DECOMPILE` spec: symbol `cl_numvisedicts`, prompt `prompt/call_llm_decompile.md`, expected section `found_gv`, reference `references/{gamever}/engine/CL_CreateVisibleEntity.{platform}.yaml`.
3. The reference annotation directs the LLM to the **non-beam insertion branch**: the same function inserts into either the visible-entity list or the beam list, and only the visible branch touches this counter/array pair. The LLM returns the instruction; shared validation resolves it against the current target and retries on mismatch.
4. Emitted fields: `gv_name`, `gv_va`, `gv_rva`, `gv_sig`, `gv_sig_va`, `gv_inst_offset`, `gv_inst_length`, `gv_inst_disp`. **No** `gv_sig_allow_across_function_boundary` field (this producer's `GV_FIELDS` omits it, and the artifact has no such key).

Concrete anchor shape from the current hl-10210 Windows artifact (evidence only): `gv_sig_va 0x10196180`, offset `0x1a`, length 6, disp 2 — i.e. `mov ecx, ds:...` inside the 0x67-byte `CL_CreateVisibleEntity`.

## Pitfalls

- **Visible branch vs beam branch (the main trap).** `CL_CreateVisibleEntity` writes either `cl_numvisedicts`/`cl_visedicts` (visible) or the beam list. The static risk is candidate selection, not a missing anchor: a response that picks the beam branch yields a valid instruction for the wrong global. The reference must keep the two branches semantically distinguished.
- `cl_numvisedicts` and `cl_visedicts` are both recovered from this one predecessor and their anchor instructions sit ~0x11 bytes apart (offset 0x1a vs 0x2b on hl-10210 Windows). A response that is off by one store silently names the sibling global.
- Unlike the `gTempEnts`/`cl_sprite_shell` group, this producer does **not** set `gv_sig_allow_across_function_boundary`, so a widened signature would be a contract violation here.
- The counter must be the visible-entity count, not a beam-list length; both are small inlined stores in the same function.
