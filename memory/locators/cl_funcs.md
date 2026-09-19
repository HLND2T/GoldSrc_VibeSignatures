---
title: cl_funcs locator
type: note
permalink: goldsrc-vibesignatures/locators/cl-funcs
tags:
  - locator
  - engine
  - gv
---

# cl_funcs

## Symbol

- **Name**: `cl_funcs`
- **Category**: `gv`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producers**: `ida_preprocessor_scripts/find-ClientDLL_HudInit-decompiles.py` (deterministic
  direct locator `_write_direct_globals`; a thin LLM step in the same finder produces the sibling
  `g_phClientModule`) and, Linux-only on the SvEngine tags,
  `ida_preprocessor_scripts/find-ClientDLL_Init-cl_funcs.py`

## Availability

- Declared in all 11 engine configs: cof-5936, hl-3248, hl-3266, hl-3329, hl-3647, hl-4554,
  hl-6153, hl-8684, hl-10210, svencoop-8948, svencoop-10257.
- Platforms: every declared platform. Until issue #161 both SvEngine tags declared `cl_funcs` as
  `platform: windows`, because their `ClientDLL_HudInit` path is not analysed; the Linux gap is now
  closed by the second producer below. (`cl_enginefuncs` already had SvEngine Linux coverage via
  `find-ClientDLL_Init-pic-enginefuncs`.)
- Inlined / absent: never inlined. It is a zero-initialised `cldll_func_t` in `.bss` (hl-10210
  Linux `0xF77F80`) or `.data` (hl-10210 Windows `0x1145EF40`).

## Predecessors

- `ClientDLL_Init.{platform}.yaml` and `ClientDLL_HudInit.{platform}.yaml` (both declared in
  `expected_input`; `ClientDLL_Init` is the one read for this symbol).

## How it is located

1. `_write_direct_globals` first loads `ClientDLL_Init.{platform}.yaml` and re-verifies the owner
   in the live IDB (`_inspect_function_via_mcp`, honouring the artifact's
   `func_sig_allow_across_function_boundary` flag). Both `cl_enginefuncs` and `cl_funcs` outputs
   must be present in `expected_outputs`, otherwise the phase bails out.
2. It walks every `call` in the `ClientDLL_Init` body and keeps those where
   `encoded_absolute_operand(call_ea, {o_mem})` resolves exactly one writable, non-executable,
   4-byte-aligned absolute address whose encoded dword matches the decoded operand. This is
   `call cl_funcs.pInitFunc`; because `pInitFunc` is slot 0 of `cldll_func_t`, the operand
   address **is** `cl_funcs`.
3. The preceding instruction must encode an `o_imm` absolute writable address (the
   `&cl_enginefuncs` argument) and an immediate `7` must appear within the four preceding
   instruction heads (the `CLDLL_INTERFACE_VERSION` argument). Same gates as `cl_enginefuncs`.
4. Exactly one `(engine, exports)` pair must survive. `cl_funcs` is emitted from the call's
   memory operand; `cl_enginefuncs` from the preceding immediate operand.
5. Emits `gv_va`, `gv_rva`, `gv_sig` (= `ClientDLL_Init` `func_sig`), `gv_sig_va`, and
   `gv_inst_offset` / `gv_inst_length` / `gv_inst_disp`; `gv_sig_allow_across_function_boundary: true`
   is copied from the owner artifact when set. On hl-10210 Windows the emitted instruction is the
   6-byte `call cl_funcs.pInitFunc` (`gv_inst_disp 0x2`).

### SvEngine Linux path (`find-ClientDLL_Init-cl_funcs`, issue #161)

The SvEngine Linux builds never reach the `ClientDLL_HudInit` locator above, so a second producer
recovers the same global from the same source statement:

```c
cl_funcs.pInitFunc( &cl_enginefuncs, CLDLL_INTERFACE_VERSION );
```

It walks `ClientDLL_Init`'s basic blocks tracking registers, pushes and `[esp+N]` argument stores,
and accepts the indirect call whose two arguments are the literal version `7` and a table whose
first twelve dwords all point into executable memory — the validated table shape already used by
`find-ClientDLL_Init-pic-enginefuncs`. The called pointer's own address is the emitted value.
Exactly one such call must survive.

Registered `platform: linux` only, so it never competes with the Windows producer for the same
artifact. Validated: svencoop-10257 L `0x30f21e0` (`call ds:(dword_30F21E0 - 2EE000h)[ebx]`),
svencoop-8948 L `0x30d2040` (`call ds:(cl_funcs - 33A000h)[ebx]`, name confirmed by that build's
`.symtab`).

## Pitfalls

- `cl_funcs` is emitted from inside the `call cl_funcs.pInitFunc` instruction, so a consumer that
  resolves it at runtime must use `gv_inst_offset + gv_inst_disp` on the `ClientDLL_Init` match —
  the encoded dword is the field address, and it equals the struct base only because `pInitFunc`
  is slot 0. A struct-layout change would silently break that equality.
- Do not confuse this global with `cl_funcs.pStudioInterface` (`cl_funcs + 0x9C`), which the
  MetaHook studio-interface transaction notes track separately. Slot members are recovered from
  the base plus a fixed offset, not from this artifact's instruction.
- Because the two globals share one discovery pass, a failure of the direct locator aborts the
  whole `find-ClientDLL_HudInit-decompiles` run and also loses `cl_enginefuncs` and
  `g_phClientModule`.
- SvEngine Windows `cl_funcs` exists, but the SvEngine `cldll_func_t` layout must not be assumed
  identical to HL's; the finder never reads a fixed slot index, only the encoded operand.
- Blob engines (`hl-3248`, `hl-3266`, `hl-3329`, `hl-3647`) are analyzed from the decrypted
  `hw.decrypt.dll`; compare by artifact VAs, not IDA display names.
- The two producers must stay platform-disjoint. Registering `find-ClientDLL_Init-cl_funcs` on
  Windows too would make one artifact ambiguous between two skills.

## Relations

- relates_to [[ClientDLL_DrawNormalTriangles]]
- relates_to [[ClientDLL_UpdateClientData]]
