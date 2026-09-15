---
title: studioapi_SetRenderModel locator
type: note
permalink: goldsrc-vibesignatures/locators/studioapi-setrendermodel
tags:
  - locator
  - engine
  - func
---

# studioapi_SetRenderModel

## Symbol

- **Name**: `studioapi_SetRenderModel`
- **Category**: `func`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-studioapi_SetRenderModel.py`,
  `ida_preprocessor_scripts/find-studioapi_SetRenderModel-svencoop.py`
  (shared `_studio_player_model_common.preprocess_studio_slot`, `SLOT_SHAPE_WRITE`)

## Availability

- Declared in 10 engine configs: hl-3248, hl-3266, hl-3329, hl-3647, hl-4554, hl-6153,
  hl-8684, hl-10210, cof-5936 (generic), svencoop-10257 (`-svencoop`).
- Platforms: Windows + Linux.
- Inlined / absent: never inlined — `engine_studio_api_t` slot 0x90. Tiny body, so the
  artifact always carries `func_sig_allow_across_function_boundary`.

## Predecessors

- None. Produces both the accessor function artifact and the `r_model` GV artifact.

## How it is located

1. Unique studio-interface diagnostic → owning function(s) → unique `engine_studio_api`
   table.
2. Read ABI slot `SLOT_OFF = 0x90`; must be a function start.
3. Structured-operand decode of the accessor body; IDA resolves absolute, SSE, x87 and
   GOTOFF forms; refs to the accessor's own GOT anchor are dropped.
4. Shape gate `SLOT_SHAPE_WRITE`: exactly one write base, zero read bases; that store target
   is `r_model`.
5. Emit `func` artifact (across-boundary sig) plus the `r_model` `gv` artifact anchored at
   the first base-referencing store, with `gv_pic_addend` on PIC sites.

## Pitfalls

- Slot 0x90 vs 0x8C: both accessors are single-store and sit next to each other; the
  reference count separates them (`r_model` 8-9 functions per binary vs `pstudiohdr` 27-32).
- SvEngine Linux resolves through an eax-anchored GOTOFF prologue while the table operand
  stays ebx-anchored.
- GOTOFF sites embed var-GOT: without the `gv_pic_addend` rebase the resolved address is
  wrong even though the signature is unique.
