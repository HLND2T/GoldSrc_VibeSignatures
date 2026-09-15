---
title: cl_visedicts locator
type: note
permalink: goldsrc-vibesignatures/locators/cl-visedicts
tags:
  - locator
  - engine
  - gv
---

# cl_visedicts

## Symbol

- **Name**: `cl_visedicts`
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
2. `LLM_DECOMPILE` spec: symbol `cl_visedicts`, prompt `prompt/call_llm_decompile.md`, expected section `found_gv`, reference `references/{gamever}/engine/CL_CreateVisibleEntity.{platform}.yaml`.
3. The candidate set is the same as for `cl_numvisedicts` — the **non-beam** insertion branch of `CL_CreateVisibleEntity`; the reference wording must separate the visible-entity *array* from the counter and from the beam list. Shared validation resolves the returned instruction against the current target and retries on mismatch.
4. Emitted fields: `gv_name`, `gv_va`, `gv_rva`, `gv_sig`, `gv_sig_va`, `gv_inst_offset`, `gv_inst_length`, `gv_inst_disp`. **No** `gv_sig_allow_across_function_boundary`.

Concrete anchor shape from the current hl-10210 Windows artifact (evidence only): `gv_sig_va 0x10196180`, offset `0x2b`, length 7, disp 3 — `mov ds:..., ...` storing the entity pointer into the array, 0x11 bytes after the `cl_numvisedicts` anchor in the same function.

## Pitfalls

- **Visible branch vs beam branch.** Same trap as `cl_numvisedicts`: the function has two insertion paths and only the visible one names this array. A plausible instruction from the beam branch is a wrong answer, not a missing one.
- **Counter vs array.** `cl_numvisedicts` (offset 0x1a) and `cl_visedicts` (offset 0x2b) are adjacent stores in the same basic block; the producer groups them under one LLM spec with `TARGETS = ["cl_numvisedicts", "cl_visedicts"]`, so both responses must be independently checked — an off-by-one pair would swap the two globals.
- The array element is a pointer-sized slot; the anchor instruction must be the store that writes the entity pointer, not the counter increment.
- No `gv_sig_allow_across_function_boundary` field is emitted by this producer.
