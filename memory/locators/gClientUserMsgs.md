---
title: gClientUserMsgs locator
type: note
permalink: goldsrc-vibesignatures/locators/gclientusermsgs
tags:
  - locator
  - engine
  - gv
---

# gClientUserMsgs

## Symbol

- **Name**: `gClientUserMsgs`
- **Category**: `gv`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-DispatchDirectUserMsg-decompiles.py`

## Availability

- Declared in 10 engine configs: cof-5936, hl-10210, hl-3248, hl-3266, hl-3329, hl-3647, hl-4554, hl-6153, hl-8684, svencoop-10257.
- Platforms: Windows + Linux.
- Inlined / absent: none observed. Official source `engine/cl_parse.c` declares `UserMsg *gClientUserMsgs` and loads it first in `DispatchDirectUserMsg` as `pList = gClientUserMsgs`.

## Predecessors

- `DispatchDirectUserMsg` (produced by `find-DispatchDirectUserMsg`, consumed via `expected_input` and `dependency_policy: required`).

## How it is located

1. Requires the current `DispatchDirectUserMsg.{platform}.yaml`; returns `False` without it.
2. `LLM_DECOMPILE` spec: symbol `gClientUserMsgs`, prompt `prompt/call_llm_decompile.md`, expected section `found_gv`, reference `references/{gamever}/engine/DispatchDirectUserMsg.{platform}.yaml`.
3. The reference annotation exposes the list-head load that starts the function (`pList = gClientUserMsgs`); the LLM returns that instruction and shared validation resolves it against the current target, retrying on mismatch.
4. Emitted fields: `gv_name`, `gv_va`, `gv_rva`, `gv_sig`, `gv_sig_va`, `gv_inst_offset`, `gv_inst_length`, `gv_inst_disp`. **No** `gv_sig_allow_across_function_boundary`.

Concrete anchor shapes from current artifacts (evidence only): hl-10210 Windows `gv_sig_va 0x101a9260` (= the function entry), offset `0x5`, length 6, disp 2 (`mov esi, [abs]`); hl-10210 Linux `gv_sig_va 0x144450`, offset `0x9`, length 6, disp 2 (`mov edi, [abs]`). Linux `0x4d67e0` matches the DWARF `UserMsg *gClientUserMsgs`.

## Pitfalls

- **Owner-string exclusion.** `FULLMATCH:UserMsg: No pfn %s %d\n` has two code xrefs; the sibling `DispatchUserMsg` owns `FULLMATCH:UserMsg: Not Present on Client %d\n`. Excluding by that Not-Present string is what isolates `DispatchDirectUserMsg` upstream. Do **not** exclude on `Malformed WeaponList request, ignoring` — that literal is missing on hl-3248/3266/3329 and the exclusion would break the older builds.
- The consumer needs the **global value** (the list-head pointer), not a code-operand field address. A `found_gv` that returns the immediate operand of the load (`disp`) or a member of a neighbouring array is wrong.
- Linux `.bss` may keep `MEMORY[0x...]` in Hex-Rays even after `set_name`; lookup by name still resolves, but the reference YAML must annotate it or the LLM can miss the load.
- MetaHook's `HudText` + first-0x50-bytes heuristic is only a hint; the owning-function diagnostic is the robust locator.
