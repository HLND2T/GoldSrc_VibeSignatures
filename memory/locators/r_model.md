---
title: r_model locator
type: note
permalink: goldsrc-vibesignatures/locators/r-model
tags:
  - locator
  - engine
  - gv
---

# r_model

## Symbol

- **Name**: `r_model`
- **Category**: `gv`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-studioapi_SetRenderModel.py`,
  `ida_preprocessor_scripts/find-studioapi_SetRenderModel-svencoop.py`

## Availability

- Declared in 10 engine configs: hl-3248, hl-3266, hl-3329, hl-3647, hl-4554, hl-6153,
  hl-8684, hl-10210, cof-5936, svencoop-10257.
- Platforms: Windows + Linux.
- Inlined / absent: always present; emitted with its accessor.

## Predecessors

- None. Produced by the same finder that produces `studioapi_SetRenderModel`.

## How it is located

1. Recover the `engine_studio_api` table and fixed slot 0x90.
2. The accessor must write exactly one writable global and read none; that store target is
   `r_model`.
3. GV artifact reuses the accessor's `func_sig` with `gv_inst_offset/length/disp` at the
   first base-referencing store; `gv_resolution_fields_via_mcp` adds `gv_pic_addend`.

## Pitfalls

- Reference count 8-9 functions per binary — small, but enough to corroborate the role and
  to separate it from the adjacent `pstudiohdr` slot.
- SvEngine Linux PIC: the site is an eax-anchored GOTOFF store; the embedded dword is
  var-GOT and must be rebased by the GOT RVA (`gv_pic_addend`) at decode time. Example:
  disp `0xA388D4` + GOT RVA `0x2EE000` = declared `0xD268D4`.
- Cross-version evidence (2026-09-10): hl-10210 hw.dll `0x104EA08C` / hw.so `0x320FD4`;
  hl-8684 `0x235AA58`; hl-3248 `0x2435490`; svencoop hw.dll `0x8DF3B24`; cof-5936
  `0x2431550`. Addresses are evidence only.
