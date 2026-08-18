---
title: gClientUserMsgs locator
type: note
permalink: goldsrc-vibesignatures/notes/g-client-user-msgs-locator
tags:
- gClientUserMsgs
- DispatchDirectUserMsg
- usermsg
- gv-finder
---

# gClientUserMsgs locator

## Trigger
Need the client user-message list head (`UserMsg *gClientUserMsgs`) in `hw.dll` / `hw.so`.

## Facts
- Official source: `engine/cl_parse.c` declares `UserMsg *gClientUserMsgs` and loads it first in `DispatchDirectUserMsg` as `pList = gClientUserMsgs`.
- MetaHook's `HudText` + first `0x50` bytes heuristic is only a hint. The robust owning-function locator is the in-function diagnostic string.
- `FULLMATCH:UserMsg: No pfn %s %d\n` has two code xrefs: `DispatchUserMsg` and `DispatchDirectUserMsg`.
- Exclude `FULLMATCH:UserMsg: Not Present on Client %d\n` (owned by `DispatchUserMsg`). Do **not** exclude `Malformed WeaponList request, ignoring` — that string is absent on hl-3248/3266/3329.
- Linux DWARF: `gClientUserMsgs` at `0x4d67e0` (`UserMsg *`) in hl-10210 `hw.so`.
- hl-10210 Windows: function `0x101a9260` / RVA `0x1a9260`; GV `0x1032f018` / RVA `0x32f018`; insn `0x101a9265` `mov esi, [abs]` disp 2, len 6.
- hl-10210 Linux: function `0x144450`; GV `0x4d67e0`; insn `0x144459` `mov edi, [abs]` disp 2, len 6.
- Consumer needs the **global value** (list-head pointer), not a code-operand field address.
- Linux `.bss` may keep `MEMORY[0x...]` in Hex-Rays even after `set_name`; lookup by name still resolves. Annotate the reference YAML.

## Correct approach
1. `find-DispatchDirectUserMsg` via the No-pfn string plus Not-Present exclude.
2. `find-DispatchDirectUserMsg-decompiles` LLM `found_gv` from annotated `DispatchDirectUserMsg` reference YAML (`hl-10210`).
3. Runtime: `gv = *(uint32_t *)(match + gv_inst_offset + gv_inst_disp)`.

## Verification
`-allgamever -modules engine -skill find-DispatchDirectUserMsg` then `-skill find-DispatchDirectUserMsg-decompiles`: 11/0/2 (hl-10210 skipped as already present).

## Scope
All engine configs (hl-*, cof-5936, svencoop-10257). Not cstrike (no engine module).
