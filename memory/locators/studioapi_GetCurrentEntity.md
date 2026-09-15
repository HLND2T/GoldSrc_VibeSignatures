---
title: studioapi_GetCurrentEntity locator
type: note
permalink: goldsrc-vibesignatures/locators/studioapi-getcurrententity
tags:
  - locator
  - engine
  - func
---

# studioapi_GetCurrentEntity

## Symbol

- **Name**: `studioapi_GetCurrentEntity`
- **Category**: `func`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-studioapi_GetCurrentEntity.py`,
  `ida_preprocessor_scripts/find-studioapi_GetCurrentEntity-svencoop.py`
  (shared `_studio_player_model_common.preprocess_studio_slot`, `SLOT_SHAPE_READ`)

## Availability

- Declared in 10 engine configs: hl-3248, hl-3266, hl-3329, hl-3647, hl-4554, hl-6153,
  hl-8684, hl-10210, cof-5936 (generic), svencoop-10257 (`-svencoop`).
- Platforms: Windows + Linux.
- Inlined / absent: never inlined — it is `engine_studio_api_t` slot 0x18. The body is tiny,
  so it has no unique strict-window `func_sig` (wildcarded bodies match 6-84 functions per
  binary) and the artifact always emits `func_sig_allow_across_function_boundary`.

## Predecessors

- None. Produces both the accessor function artifact and the `currententity` GV artifact.

## How it is located

1. Same root as `studioapi_SetupPlayerModel`: the unique studio-interface diagnostic
   (`client .dll` wording for GoldSrc/HL25/CoF, `client library` for SvEngine) → owning
   function(s) → the unique `engine_studio_api` table (`validate_table_run`: writable data,
   ≥43 of the first 45 dwords are non-zero code pointers; SvEngine 47/48 entries).
2. Read fixed ABI slot `SLOT_OFF = 0x18`; it must be an exact function start.
3. Decode the accessor body with structured operands only. `disp32_operand_offset` keeps
   instructions that carry a real 4-byte displacement operand, so pointer-chasing `[reg]`
   loads and `[esp+disp8]` stack operands never pollute the shape. Direction comes from the
   mnemonic (`mov`/`lea`/`movss`/`fld` = read, `fst`/`fstp`/`mov-to-mem` = write). Data refs
   are resolved by IDA (`writable_refs`), which covers absolute, SSE `movss`, x87 `fld/fstp`
   and GOTOFF `[reg+disp32]`; refs equal to the accessor's own GOT anchor are dropped.
4. Shape gate `SLOT_SHAPE_READ`: exactly one read base cluster and zero write bases.
5. Emit `func` artifact (accessor, across-boundary sig) plus the `currententity` `gv`
   artifact using the accessor's `func_sig` with `gv_inst_offset/length/disp` pointing at the
   first base-referencing instruction; `gv_resolution_fields_via_mcp` adds `gv_pic_addend`
   when the site is register-relative.

## Pitfalls

- Decode slot 0x18, not the neighbouring 0x8C/0x90/0x9C slots.
- SvEngine Linux accessors anchor the global through an **eax**-anchored GOTOFF prologue
  while the owner function still anchors its table operand on **ebx** (`add ebx, imm32`,
  GOT anchor RVA 0x2EE000). Do not share one anchor register between the two stages.
- A GOTOFF site embeds var-GOT with no relocation: the runtime dword must be rebased by the
  GOT RVA (`gv_pic_addend`), otherwise the resolved address is wrong even though the
  signature is unique.
- Reference counts corroborate the role: `currententity` is referenced by 39-47 functions
  per binary.
