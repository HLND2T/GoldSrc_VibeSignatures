---
title: g_ppStudioInterfaceCall locator
type: note
permalink: goldsrc-vibesignatures/locators/g-ppstudiointerfacecall
tags:
  - locator
  - engine
  - gv
---

# g_ppStudioInterfaceCall

## Symbol

- **Name**: `g_ppStudioInterfaceCall`
- **Category**: `gv`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: none in this repo. `g_ppStudioInterfaceCall` is a **MetaHook-side name**; the
  engine object it denotes is `&cl_funcs.pStudioInterface`, a `cldll_func_t` member slot at
  `cl_funcs + 0x9C`. There is no `find-*` script for it — everything below is the anchor
  approach the notes recommend for a future finder.

## Availability

- Not declared in any config (no finder exists).
- Engine modules only (`hw.dll` / `hw.so`).
- Inlined / absent: the *slot* always exists; it is the reference *instruction* that varies.
  `cl_funcs.pStudioInterface` is a real global, so it survives even where the owning function
  body is inlined. On hl-10210 the assignment is optimized away entirely (the slot keeps the
  value written during `ClientDLL_Init`), and the call is `mov eax, [slot]; call eax`
  (`FF D0`), not `FF 15 [slot]`.

## Predecessors

- None documented. A future finder would root on the `ClientDLL_CheckStudioInterface`
  diagnostic literal plus `&cl_funcs.pStudioInterface`; the two studio tables
  (`pStudioAPI`, `engine_studio_api`) are the call arguments that validate the slot.

## How it is located

Recommended chain (source `engine/cdll_int.c`; `cl_funcs.pStudioInterface(STUDIO_INTERFACE_VERSION,
&pStudioAPI, &engine_studio_api)`):

1. Anchor the **exact** diagnostic literal, not a substring:
   - GoldSrc: `"Couldn't get client .dll studio model rendering interface.  Version mismatch?\n"`
     (two spaces after the period)
   - SvEngine: `"Couldn't get client library studio model rendering interface. Version mismatch?\n"`
     (one space)
2. Collect **all** code xrefs of the literal. Accept one or two owning functions, but require
   them to collapse onto the **same** slot address (hl-10210 Linux has an inlined copy in
   `ClientDLL_HudInit` and a standalone DWARF `ClientDLL_CheckStudioInterface`, both loading
   the same slot).
3. Near the xref, identify the instruction whose decoded immediate address is
   `cl_funcs + 0x9C` and which is invoked with version `1` plus the two studio tables — i.e.
   the `mov`/`cmp`/`call dword ptr [abs]` that is `test`ed and then called. Do **not** use
   "the first `FF 15` within 0x50 bytes before the string": on HL25 that `FF 15` is the
   `GetProcAddress` IAT call.
4. Persist as a true GV: `gv_address = *(uint32_t *)(matched_instruction + gv_inst_disp)`.
   The consumer needs the **global value**, not a code-operand field, so the `FF 15` encoding
   is optional/implementation detail:
   - `FF 15 [slot]` → MetaHook fills `g_ppStudioInterfaceCall` and uses the indirect patch;
   - `mov r32, [slot]; call r32` → MetaHook leaves it NULL and uses the direct patch.

## Pitfalls

- MetaHook's own extractor (`FF 15 <imm32>` inside a 0x50-byte window) is a compiler-form
  **hint only** — it never fires on hl-10210 (Windows or Linux) and would leave the value
  NULL while the slot still exists. Do not use it as the locator.
- Do not key on the `+0x9C` offset as the sole evidence: `cldll_func_t` layout is verified at
  `+0x9C` only on the checked HL25 builds; a very old client with fewer leading members could
  shift it. Treat it as a cross-check against the `cl_funcs` base, validated together with the
  `(1, &pStudioAPI, &engine_studio_api)` argument shape.
- Do not use a raw VA/RVA as a cross-version anchor, and do not use the bare
  `"studio model rendering"` substring.
- Reference evidence (2026-08-18, addresses are evidence only): hl-10210 Windows string
  `0x102b4418`, one xref `ClientDLL_HudInit 0x10196e50` (check inlined), slot `0x1145efdc`
  (`cl_funcs 0x1145EF40 + 0x9C`, RVA `0x145EFDC`), slot-reference instruction `0x10196e93`
  (`A1 DC EF 45 11`, disp 1, len 5). hl-10210 Linux string `0x259620`, two xrefs —
  inlined `ClientDLL_HudInit 0x159020` and standalone `0x1593F0` — both loading slot
  `0xF7801C` (`cl_funcs 0xF77F80 + 0x9C`), instructions `0x1590c9` / `0x159421`
  (`A1 1C 80 F7 00`, disp 1, len 5).
