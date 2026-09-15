---
title: allow_cheats locator
type: note
permalink: goldsrc-vibesignatures/locators/allow-cheats
tags:
  - locator
  - engine
  - gv
---

# allow_cheats

## Symbol

- **Name**: `allow_cheats`
- **Category**: `gv`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-CL_Set_ServerExtraInfo-decompiles.py`

## Availability

- Declared in 1 config: svencoop-10257.
- Platforms: Windows + Linux.
- Inlined / absent: none observed. SvEngine-only; HL/cof/CS/CZ/CZDS do not declare it.

## Predecessors

- `CL_Set_ServerExtraInfo.{platform}.yaml` (produced by `find-CL_Set_ServerExtraInfo`, consumed via `expected_input`, `dependency_policy: required`).

## How it is located

1. Uses the generic `preprocess_common_skill` LLM_DECOMPILE path with `prompt/call_llm_decompile.md` and reference YAML `references/{gamever}/engine/CL_Set_ServerExtraInfo.{platform}.yaml`; the resolved gamever here is svencoop-10257.
2. The predecessor's recovered disassembly/pseudocode is the current-target evidence; the LLM performs the symbol mapping and must return `found_gv` naming `allow_cheats`.
3. Emits a GV YAML with the standard `gv_name`/`gv_va`/`gv_rva`/`gv_sig`/`gv_sig_va`/`gv_inst_offset`/`gv_inst_length`/`gv_inst_disp` fields. No `gv_sig_allow_across_function_boundary` for this symbol.

## Pitfalls

- This is a decompiles finder: its anchor quality depends entirely on the predecessor handler being correct. The `svc_sendextrainfo` handler is read from the named `cl_parsefuncs` entry, so a wrong `cl_parsefuncs` propagates here.
- The reference YAML key is `{gamever}`; only svencoop-10257 is configured, so no cross-family address reuse is possible — but reference addresses are evidence only and must never become selectors.
