---
title: cl_viewentity locator
type: note
permalink: goldsrc-vibesignatures/locators/cl-viewentity
tags:
  - locator
  - engine
  - gv
---

# cl_viewentity

## Symbol

- **Name**: `cl_viewentity`
- **Category**: `gv`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-CL_Parse_SetView-decompiles.py`

## Availability

- Declared in 10 engine configs: cof-5936, hl-10210, hl-3248, hl-3266, hl-3329, hl-3647, hl-4554, hl-6153, hl-8684, svencoop-10257.
- Platforms: Windows + Linux.
- Inlined / absent: none observed; the global is always the server-selected view-entity index storage.

## Predecessors

- `CL_Parse_SetView` (produced by `find-CL_Parse_SetView`, consumed via `expected_input` and `dependency_policy: required`).

## How it is located

1. Requires the current `CL_Parse_SetView.{platform}.yaml`; returns `False` without it.
2. `LLM_DECOMPILE` spec: symbol `cl_viewentity`, prompt `prompt/call_llm_decompile.md`, expected section `found_gv`, reference `references/{gamever}/engine/CL_Parse_SetView.{platform}.yaml`.
3. The reference annotation directs the LLM to the **server-selected view-entity index**, explicitly *not* the viewmodel entity. Shared validation resolves the returned instruction/operand against the current target and retries on mismatch.
4. Emitted fields: `gv_name`, `gv_va`, `gv_rva`, `gv_sig`, `gv_sig_va`, `gv_inst_offset`, `gv_inst_length`, `gv_inst_disp`, plus `gv_sig_allow_across_function_boundary:true`. The shared emitter also preserves `gv_pic_addend` / `gv_address_offset` when address recovery produces them.

Concrete anchor shapes from current artifacts (evidence only): hl-10210 Windows `gv_sig_va 0x101aa340`, offset `0x5`, length 5, disp 1 (`mov ds:..., eax` on the 0xB handler); Sven Linux `gv_va 0x1bd9a48`, `gv_pic_addend 0x15d7d60`, offset `0x1a`, length 6, disp 2.

## Pitfalls

- **Register-relative store address (Sven Linux, observed failure).** The LLM correctly selected `mov ds:dword_601CE8[edx], eax`, but IDA's mapped-data xref named the encoded *displacement* (0x601ce8), not the effective address. The fix requires base resolution along all reachable predecessors: EDX = 0x15d7d60, so the target is `0x15d7d60 + 0x601ce8 = 0x1bd9a48`. The resulting `gv_pic_addend` must be preserved — dropping it silently resolves to the wrong runtime address.
- A proven effective address overrides the displacement xref; failure must never fall back to the displacement xref. Unknown/clobbered/ambiguous bases stay unresolved and the finder fails closed.
- Do not confuse this global with the viewmodel entity: the reference wording exists specifically to prevent that.
- `gv_sig_allow_across_function_boundary:true` is always set (the anchor lives in the tiny stub, whose signature must cross into the following bytes).
