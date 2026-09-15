---
title: studioapi_StudioSetHeader locator
type: note
permalink: goldsrc-vibesignatures/locators/studioapi-studiosetheader
tags:
  - locator
  - engine
  - func
---

# studioapi_StudioSetHeader

## Symbol

- **Name**: `studioapi_StudioSetHeader`
- **Category**: `func`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-studioapi_StudioSetHeader.py`,
  `ida_preprocessor_scripts/find-studioapi_StudioSetHeader-svencoop.py`
  (shared `_studio_player_model_common.preprocess_studio_slot`, `SLOT_SHAPE_WRITE`)

## Availability

- Declared in 10 engine configs: hl-3248, hl-3266, hl-3329, hl-3647, hl-4554, hl-6153,
  hl-8684, hl-10210, cof-5936 (generic), svencoop-10257 (`-svencoop`).
- Platforms: Windows + Linux.
- Inlined / absent: never inlined — `engine_studio_api_t` slot 0x8C. Tiny body, so the
  artifact always carries `func_sig_allow_across_function_boundary`.

## Predecessors

- None. Produces both the accessor function artifact and the `pstudiohdr` GV artifact.

## How it is located

1. Unique studio-interface diagnostic → owning function(s) → unique `engine_studio_api`
   table (`validate_table_run`; SvEngine 47/48 entries).
2. Read ABI slot `SLOT_OFF = 0x8C`; must be a function start.
3. Decode the accessor with structured operands (real disp32 operands only, IDA-resolved data
   refs, GOT-anchor refs dropped).
4. Shape gate `SLOT_SHAPE_WRITE`: exactly one write base and zero read bases. That store
   target is `pstudiohdr`.
5. Emit `func` artifact (across-boundary sig) plus the `pstudiohdr` `gv` artifact whose
   `gv_inst_offset/length/disp` point at the first base-referencing store; PIC sites get
   `gv_pic_addend`.

## Pitfalls

- Slot 0x8C is adjacent to slot 0x90 (`studioapi_SetRenderModel`); do not let the two
  collapse. The GV roles are separated by reference count — `pstudiohdr` is referenced by
  27-32 functions per binary, `r_model` by 8-9.
- SvEngine Linux resolves the global through an eax-anchored GOTOFF prologue while the table
  operand is ebx-anchored; keep the two anchors distinct.
- GOTOFF sites embed var-GOT with no relocation; the runtime decoder must add `gv_pic_addend`.
