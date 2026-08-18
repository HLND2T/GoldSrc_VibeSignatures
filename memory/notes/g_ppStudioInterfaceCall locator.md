---
title: g_ppStudioInterfaceCall locator
type: note
permalink: goldsrc-vibesignatures/notes/g-pp-studio-interface-call-locator
tags:
- g_ppStudioInterfaceCall
- cl_funcs
- pStudioInterface
- ClientDLL_CheckStudioInterface
- gv-finder
---

# g_ppStudioInterfaceCall locator

## Trigger
Need the studio-interface callback pointer slot that MetaHook names `g_ppStudioInterfaceCall`.

## Facts
- Official source: `engine/cdll_int.c` `ClientDLL_CheckStudioInterface` assigns and calls `cl_funcs.pStudioInterface(STUDIO_INTERFACE_VERSION, &pStudioAPI, &engine_studio_api)`.
- DWARF name on `bin/hl-10210/engine/hw.so`: `cl_funcs.pStudioInterface` (`cldll_func_t` member at `cl_funcs+0x9C`). Owning function name: `ClientDLL_CheckStudioInterface`.
- MetaHook's `FF 15 <imm32>` extractor is only a compiler-form hint. hl-10210 Windows/Linux use `mov eax,[slot]; call eax` (`FF D0`), so MetaHook leaves `g_ppStudioInterfaceCall` NULL. The slot still exists.
- Robust owning-function literal: `FULLMATCH:Couldn't get client .dll studio model rendering interface.  Version mismatch?\n` (GoldSrc). Sven uses `FULLMATCH:Couldn't get client library studio model rendering interface. Version mismatch?\n`.
- hl-10210 Windows: string once, one xref, function `ClientDLL_HudInit` `0x10196e50` (inlined check). Slot `0x1145efdc` / RVA `0x145efdc`. Insn `0x10196e93` `A1 DC EF 45 11` disp 1, len 5.
- hl-10210 Linux: string once, two code xrefs — inlined copy in `ClientDLL_HudInit` `0x159020` and standalone DWARF `ClientDLL_CheckStudioInterface` `0x1593f0`. Both load the same slot `0xf7801c` / RVA `0xf7801c`. Insn `0x1590c9` / `0x159421` `A1 1C 80 F7 00` disp 1, len 5.
- Consumer needs the **global value** (address of `cl_funcs.pStudioInterface`), not a code-operand field. `FF 15` is optional encoding.
- Do not use the MetaHook 0x50-byte `FF 15` window as the locator. Recover the slot from the verified call arguments `(1, &pStudioAPI, &engine_studio_api)` after the HUD_GetStudioModelInterface GetProcAddress/dlsym site.

## Correct approach
1. Anchor the exact GoldSrc/Sven diagnostic string (not a substring of "studio model rendering" alone).
2. Accept one or two owning functions if they collapse to one slot address.
3. Select the `mov`/`cmp`/`call dword ptr [abs]` whose decoded immediate is `cl_funcs+0x9C` and is invoked with version 1 plus the two studio tables.
4. Persist as a true GV: `gv_address = *(uint32_t *)(matched_instruction + gv_inst_disp)`.

## Verification
Owned `IdaMcpLifecycle` on `bin/hl-10210/engine/hw.dll` and `hw.so`; `survey_binary` identity matched SHA-256; `server_health` ok; string count 1; slot equals `cl_funcs+0x9C`.

## Scope
Engine modules (`hw.dll` / `hw.so`). Windows may inline the check into `ClientDLL_HudInit`. Linux DWARF may keep both the inlined copy and a standalone `ClientDLL_CheckStudioInterface`.
