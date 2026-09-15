---
title: DM_PlayerState locator
type: note
permalink: goldsrc-vibesignatures/locators/dm-playerstate
tags:
  - locator
  - engine
  - gv
---

# DM_PlayerState

## Symbol

- **Name**: `DM_PlayerState` (engine per-client player-model state array)
- **Category**: `gv`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-DM_PlayerState.py`

## Availability

- Declared in 10 engine configs: hl-3248, hl-3266, hl-3329, hl-3647, hl-4554, hl-6153,
  hl-8684, hl-10210, cof-5936, svencoop-10257.
- Platforms: Windows + Linux.
- Inlined / absent: always present as a statically zero-filled array.

## Predecessors

- `studioapi_SetupPlayerModel` (produced by `find-studioapi_SetupPlayerModel{,-svencoop}`,
  consumed via `expected_input`) — the owner function whose body is scanned.

## How it is located

1. Load the verified `studioapi_SetupPlayerModel` artifact and require its `func_va` to be an
   exact function start in the current IDB.
2. `model_base_registers` collects the base register of every `[reg+0x208]` access in the
   body (`MODEL_FIELD_OFFSET = 0x208`, `player_model_t.model`).
3. Walk the body in instruction order. A candidate is accepted when either:
   - **Form A**: the instruction's 32-bit destination register is one of those `+0x208`
     bases, or
   - **Form B** (hl-10210 hw.dll): MSVC folds the field into an absolute displacement and
     indexes directly, so the function carries operands at `V+0x104` and `V+0x208`
     (both must be present in the body's operand set).
4. Reject pointer-to-const slots (`is_pointer_slot`): if the candidate's first dword points
   into const/code memory it is a pointer slot (e.g. a cvar `"developer"` name pointer), not
   the state array. `DM_PlayerState` is the array itself, statically zero-filled.
5. Emit the GV with `gv_inst_offset/length/disp` at the accepted instruction; the owner's
   `func_sig` supplies `gv_sig`; `gv_resolution_fields_via_mcp` adds `gv_pic_addend`.

## Pitfalls

- **Element stride is 0x20C on every family.** hl builds also stride an extended `cl.players`
  at **0x250** — never confuse the two. Only DM is reached through `+0x208` (and `+0x104`),
  and `cl.players` never feeds a `+0x208` access.
- Structured operand extraction only: a raw byte-window dword scan decodes opcode bytes of
  e.g. `mov eax, [esi+208h]` or an `imul reg, reg, 20Ch` window into mapped `.data`
  addresses and misattributes them as globals.
- Register reuse across forms: a dest register that matches a `+0x208` base set can also be
  the destination of an unrelated load (SvEngine `"developer"` `lea`). `is_pointer_slot`
  rejects that case.
- Codegen varies and all forms must survive: direct `lea`/`imul+add` (MSVC hl/cof, SvEngine
  Windows), stack-slot round-trips (cof debug build), register recomputation as `DM+0x104`
  (hl-10210 hw.dll picks the earlier base `lea`), and SvEngine Linux PIC `lea reg,
  [ebx+disp32]` with the ebx GOT anchor from the `call thunk; add ebx, imm32` prologue.
- The PIC `o_displ` address is the module-relative displacement and can land in a writable
  segment by chance — when a PIC decode matches, use only the GOT-anchored resolution.
- The locator requires the accepted instruction to lie in `[setup_va, setup_va + 0x400)`.
