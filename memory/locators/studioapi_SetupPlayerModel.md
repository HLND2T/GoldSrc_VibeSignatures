---
title: studioapi_SetupPlayerModel locator
type: note
permalink: goldsrc-vibesignatures/locators/studioapi-setupplayermodel
tags:
  - locator
  - engine
  - func
---

# studioapi_SetupPlayerModel

## Symbol

- **Name**: `studioapi_SetupPlayerModel`
- **Category**: `func`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-studioapi_SetupPlayerModel.py`,
  `ida_preprocessor_scripts/find-studioapi_SetupPlayerModel-svencoop.py`
  (both drive `_studio_player_model_common.preprocess_studio_setup_player_model`)

## Availability

- Declared in 10 engine configs: hl-3248, hl-3266, hl-3329, hl-3647, hl-4554, hl-6153,
  hl-8684, hl-10210, cof-5936 (generic finder) and svencoop-10257 (`-svencoop` variant).
- Platforms: Windows + Linux. Not applicable to cstrike/czero/czeror (no engine module here).
- Inlined / absent: never inlined — it is `engine_studio_api_t` slot 0x7C, an ABI-table entry
  the client calls through the table. The *anchor* is what differs per family, not the symbol.

## Predecessors

- None. This is the root of the whole studio player-model DAG; `DM_PlayerState`,
  `cl_players_model`, `Host_IsSinglePlayerGame`, `R_StudioChangePlayerModel` and the
  callsite patches all consume its artifact via `expected_input`.

## How it is located

1. Find the exact `ClientDLL_CheckStudioInterface` interface-mismatch literal and require
   exactly one hit. GoldSrc/HL25/CoF wording is
   `"Couldn't get client .dll studio model rendering interface.  Version mismatch?\n"`
   (two spaces after the period); SvEngine uses
   `"Couldn't get client library studio model rendering interface. Version mismatch?\n"`
   — this string is the only difference between the base and `-svencoop` finders.
2. Resolve the literal's owning function(s). On Windows the check is usually inlined into
   `ClientDLL_HudInit`; Linux may have two owners (an inlined copy plus a standalone DWARF
   `ClientDLL_CheckStudioInterface`).
3. Walk each owner's instructions for writable-data operands: absolute dword operands
   (`absolute_data_operands`) and, when the owner has an ebx GOT anchor
   (`call thunk; add ebx, imm32`), PIC `lea reg, [ebx+disp32]` sites (`pic_ebx_displacements`).
4. Validate each candidate `validate_table`: the target must be writable non-exec data, at
   least 43 of its first 45 dwords (`TABLE_DWORDS`) must be non-zero *code* pointers
   (`MIN_TABLE_CODE_RUN = 43`), and dword at `SETUP_SLOT_OFFSET = 0x7C` must be an exact
   function start. Require exactly one surviving table — the locator collapses on the unique
   table VA, not on the owner.
5. Semantic gate: the slot-0x7C function must reference the exact string
   `"models/player/%s/%s.mdl"`.
6. Emit `func_va`/`func_sig` for the slot function. Strict-window inspection is tried first;
   for PIC prologues whose 64-token window is almost fully wildcarded it retries with
   `func_sig_allow_across_function_boundary`.

## Pitfalls

- Slot 0x7C is index 31 of `engine_studio_api_t` (`common/r_studioint.h`); SvEngine ships
  47/48 ABI-compatible entries, which is why the table-run gate is a *minimum* (43), not an
  exact 45.
- `is_exec(0)` must be rejected explicitly: ELF image base 0 maps address 0 into `.text`, so
  a naive "executable pointer" test would count a zero slot as a code pointer.
- Two Linux owners are normal and both reference the same table; do not key the result on a
  single owner or you will pick the wrong function when the DWARF copy and the inlined copy
  disagree.
- `"models/player/%s/%s.mdl"` is also owned by `R_StudioDrawPlayer`; here it is only used to
  validate the *slot* function, never to disambiguate the table.
- Discovery never uses a byte signature or a prior artifact signature.
