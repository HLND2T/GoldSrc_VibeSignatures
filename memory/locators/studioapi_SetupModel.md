---
title: studioapi_SetupModel locator
type: note
permalink: goldsrc-vibesignatures/locators/studioapi-setupmodel
tags:
  - locator
  - engine
  - func
---

# studioapi_SetupModel

## Symbol

- **Name**: `studioapi_SetupModel`
- **Category**: `func` plus globals `pbodypart` (`gv`) and `psubmodel` (`gv`)
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-studioapi_SetupModel.py`,
  `ida_preprocessor_scripts/find-studioapi_SetupModel-svencoop.py`
  (shared `ida_preprocessor_scripts._studio_setup_common.preprocess_studio_setup_model`)

## Availability

- Declared in 11 engine configs: generic GoldSrc/HL25/CoF finders, SvEngine `-svencoop`.
- Platforms: Windows + Linux.
- Inlined / absent: the slot itself is never missing. Windows is a thin wrapper that
  calls `R_StudioSetupModel`. GoldSrc/HL25 Linux and SvEngine Linux inline that body
  into this wrapper and still perform the two out-param stores.

## Predecessors

- None. The engine studio API table is re-derived from the interface diagnostic each run.

## How it is located

1. Unique studio-interface diagnostic → owning function(s) → unique `engine_studio_api`
   table (`locate_studio_slot`, slot 20, offset `0x50`).
2. The wrapper must contain exactly two out-param stores of a writable-data address, in
   source order: `*ppbodypart = &pbodypart` then `*ppsubmodel = &psubmodel`.
   - Windows / non-PIC Linux: `mov dword ptr [reg], offset global`.
   - SvEngine Linux PIC: `lea tmp, [ebx+disp32]` then `mov [outparam], tmp`.
3. Direct `mov pbodypart, computed` stores (the inlined private body) are ignored; they
   write the pointer value, not `&global`.
4. The tiny Windows wrapper uses the across-boundary signature window.

## Pitfalls

- Slot 20 is `studioapi_SetupModel`, not `R_StudioSetupModel`.
- Do not sort `pbodypart` / `psubmodel` by VA: on hl-10210 Linux `psubmodel` is the
  lower address.
- MetaHook types these as `**` because it captures `&global`; the objects themselves
  are `mstudiobodyparts_t *` / `mstudiomodel_t *`.
- GOTOFF lea sites need `gv_pic_addend`.
