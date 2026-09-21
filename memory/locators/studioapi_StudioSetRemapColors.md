---
title: studioapi_StudioSetRemapColors locator
type: note
permalink: goldsrc-vibesignatures/locators/studioapi-studiosetremapcolors
tags:
  - locator
  - engine
  - func
---

# studioapi_StudioSetRemapColors

## Symbol

- **Name**: `studioapi_StudioSetRemapColors`
- **Category**: `func` plus globals `r_topcolor` (`gv`, int) and `r_bottomcolor` (`gv`, int)
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-studioapi_StudioSetRemapColors.py`
  (shared `ida_preprocessor_scripts._studio_player_model_common.preprocess_studio_slot`,
  `SLOT_SHAPE_WRITE_PAIR`)

## Availability

- Declared in 11 engine configs: hl-3248, hl-3266, hl-3329, hl-3647, hl-4554, hl-6153,
  hl-8684, hl-10210, cof-5936, svencoop-8948, svencoop-10257.
- Platforms: Windows + Linux (no `platform:` gating). The finder tries both HL and
  SvEngine ClientDLL_CheckStudioInterface diagnostics.
- Inlined / absent: never inlined — it is `engine_studio_api_t` slot 30 (`0x78`),
  immediately before `studioapi_SetupPlayerModel` at `0x7C`. Tiny 19-22 byte
  accessor, so the artifacts carry `func_sig_allow_across_function_boundary`.

## Predecessors

- None. The engine studio API table is re-derived from the interface diagnostic each run.

## How it is located

1. For each diagnostic in `(HL_STUDIO_STRING, SVC_STUDIO_STRING)`, call
   `locate_studio_slot(..., 0x78)` and require a unique table plus a function-start
   slot pointer.
2. Shape gate `SLOT_SHAPE_WRITE_PAIR`: zero global reads and exactly two distinct
   writable-data int stores, recovered from `insns` in instruction order.
   - First store is `r_topcolor` (parameter `top`).
   - Second store is `r_bottomcolor` (parameter `bottom`).
3. Windows / non-PIC Linux encode `mov ds:global, arg`. SvEngine Linux uses an
   eax-anchored GOTOFF prologue (`call get_pc_thunk; add eax, GOT; mov [eax+off], arg`)
   and emits `gv_pic_addend`.
4. Linux ELF names match the artifacts: `studioapi_StudioSetRemapColors`,
   `r_topcolor`, `r_bottomcolor`. SvEngine 8948 mangles the function and keeps the
   two ints as file-scope statics (`_ZL10r_topcolor` / `_ZL13r_bottomcolor`).

## Pitfalls

- Slot 0x78 is `studioapi_StudioSetRemapColors`, not `studioapi_SetupPlayerModel`
  (0x7C) or `StudioSetupSkin` (0x74).
- `cluster_bases` merges values within 8 bytes, so adjacent ints collapse to the
  lower VA. `write_bases` is VA-sorted, so reversed layouts swap the two names.
  Recover from instruction order only.
- The two ints may be adjacent (hl-10210 Linux, SvEngine Linux), 16 bytes apart
  (hl-8684 Linux), or far apart (Windows builds).
- GOTOFF sites embed var-GOT; the runtime decoder must add `gv_pic_addend`.

## Evidence

- hl-10210 `hw.dll` `0x101F3CA0` -> `0x104F0EE4` / `0x1050F6E8`
- hl-10210 `hw.so` `0xC6370` -> `0x300D44` / `0x300D40` (VA reversed)
- hl-8684 `hw.so` `0x129D30` -> `0x322FF0` / `0x323000`
- svencoop-10257 `hw.dll` `0x1D92C20` -> `0x8DFA97C` / `0x8E13D80`
- svencoop-10257 `hw.so` `0x9FDF0` -> `0xD01244` / `0xD01240` (GOT `0x2EE000`)
- cof-5936 `hw.dll` `0x1DC3B14` -> `0x248B59C` / `0x242F94C` (VA reversed)
- hl-3248 `hw.decrypt.dll` `0x1D92890` -> `0x2482F70` / `0x2433888` (VA reversed)
