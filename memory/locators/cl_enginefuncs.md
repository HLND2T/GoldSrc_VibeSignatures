---
title: cl_enginefuncs locator
type: note
permalink: goldsrc-vibesignatures/locators/cl-enginefuncs
tags:
  - locator
  - engine
  - gv
---

# cl_enginefuncs

## Symbol

- **Name**: `cl_enginefuncs`
- **Category**: `gv`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**:
  - `ida_preprocessor_scripts/find-ClientDLL_HudInit-decompiles.py` — deterministic direct
    locator (`_write_direct_globals`), all Windows builds and hl-10210/hl-8684 Linux.
  - `ida_preprocessor_scripts/find-ClientDLL_Init-pic-enginefuncs.py` — svencoop-10257 Linux
    (PIC/GOT-relative form) only.

## Availability

- Declared in 10 configs: cof-5936, hl-10210, hl-3248, hl-3266, hl-3329, hl-3647, hl-4554,
  hl-6153, hl-8684, svencoop-10257.
- Platforms: Windows + Linux. Linux artifacts exist for hl-10210, hl-8684 and svencoop-10257;
  `cl_enginefuncs` is the only one of the three client-engine globals that svencoop-10257 builds
  for both platforms.
- Inlined / absent: the global always exists. Note that the SvEngine `cl_enginefuncs` **layout
  differs** from HL's (slot 11 is not a function start), so HL slot indices must not be reused
  there.

## Predecessors

- `ClientDLL_Init.{platform}.yaml` and `ClientDLL_HudInit.{platform}.yaml` (both listed in
  `expected_input`); only `ClientDLL_Init` is actually read by the code paths, and
  `ClientDLL_HudInit` gates the sibling `g_phClientModule` LLM step of the same finder.
- For the PIC variant: `ClientDLL_Init.{platform}.yaml` only.

## How it is located

### `find-ClientDLL_HudInit-decompiles` (HL and SvEngine Windows, HL Linux)

1. Load `ClientDLL_Init.{platform}.yaml`, re-verify the owner in the live IDB
   (`_inspect_function_via_mcp`, honouring its `func_sig_allow_across_function_boundary` flag).
2. Walk every `call` in the `ClientDLL_Init` body. `encoded_absolute_operand(call_ea, {o_mem})`
   must find exactly one memory operand whose encoded dword equals the decoded target address, is
   4-byte aligned and lives in a writable, non-executable segment. That is the
   `call cl_funcs.pInitFunc` instruction, whose operand address is `cl_funcs` itself (pInitFunc is
   slot 0 of `cldll_func_t`).
3. The *immediately preceding* instruction head must encode exactly one `o_imm` absolute address
   under the same writability/alignment rules — that is `push offset cl_enginefuncs` (Windows) or
   `mov [esp+…], offset cl_enginefuncs` (Linux). The two addresses must differ.
4. Within the four instruction heads preceding that load, an immediate equal to
   `CLIENT_DLL_INTERFACE_VERSION = 7` must appear (the version argument of the same call).
5. Exactly one surviving `(engine, exports)` pair is required.
6. Emits for `cl_enginefuncs`: `gv_va`, `gv_rva`, `gv_sig` = the `ClientDLL_Init` `func_sig`,
   `gv_sig_va`, and `gv_inst_offset` / `gv_inst_length` / `gv_inst_disp` measured from
   `ClientDLL_Init`, plus `gv_sig_allow_across_function_boundary: true` when the owner artifact
   carries that flag.

### `find-ClientDLL_Init-pic-enginefuncs` (svencoop-10257 Linux)

1. Abstract-interpret every basic block of the verified `ClientDLL_Init` block, tracking
   immediate/`lea`-loaded register values and stack arguments.
2. At each indirect `call`, the stack slot at `+4` must be the immediate `7` and the slot at `+0`
   must be a candidate table address: 4-byte aligned, non-executable, whose **first twelve** dwords
   all point into executable segments (the SDK's initial `cl_enginefunc_t` entries are function
   pointers on every x86 peer).
3. Require exactly one unique candidate across all blocks; emit `gv_va` / `gv_rva`, the
   `ClientDLL_Init` signature as `gv_sig`, and the instruction offset/length/disp, plus the
   `gv_resolution_fields_via_mcp` metadata (this is where SvEngine's `gv_pic_addend` appears — the
   encoded displacement is not the absolute VA).

## Pitfalls

- The two producers are disjoint by platform/config, but they agree on the artifact shape, so a
  consumer must not assume `gv_sig_va` is always a Windows-absolute instruction: on SvEngine Linux
  the `gv_pic_addend` field is part of the resolution contract.
- The `pInitFunc` call is not the first `cl_funcs` reference in `ClientDLL_Init` (the body also
  writes `cl_funcs.pInitFunc`, `pHudVidInitFunc`, memsets the struct, etc.). The finder keys on
  the *encoded writable absolute operand* plus the version-7 argument, not on "the first
  `cl_funcs` access".
- For the PIC variant, requiring the first twelve entries to be code pointers is the whole
  discrimination between the engine table and the zero-initialised `cl_funcs`/`engine_studio_api`
  neighbours — those have no executable dword 0 and are rejected.
- `_write_direct_globals` is a hard gate: if it fails, the whole
  `find-ClientDLL_HudInit-decompiles` run returns False, so `cl_funcs` and `g_phClientModule` are
  lost along with this symbol.
- Blob engines (`hl-3248`, `hl-3266`, `hl-3329`, `hl-3647`) are analyzed from the decrypted
  `hw.decrypt.dll`; name/VA comparisons must come from artifacts, not IDA display names.
