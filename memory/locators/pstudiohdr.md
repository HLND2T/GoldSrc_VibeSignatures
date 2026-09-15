---
title: pstudiohdr locator
type: note
permalink: goldsrc-vibesignatures/locators/pstudiohdr
tags:
  - locator
  - engine
  - gv
---

# pstudiohdr

## Symbol

- **Name**: `pstudiohdr`
- **Category**: `gv`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-studioapi_StudioSetHeader.py`,
  `ida_preprocessor_scripts/find-studioapi_StudioSetHeader-svencoop.py`

## Availability

- Declared in 10 engine configs: hl-3248, hl-3266, hl-3329, hl-3647, hl-4554, hl-6153,
  hl-8684, hl-10210, cof-5936, svencoop-10257.
- Platforms: Windows + Linux.
- Inlined / absent: always present; emitted with its accessor, never standalone.

## Predecessors

- None. Produced by the same finder that produces `studioapi_StudioSetHeader`.

## How it is located

1. Recover the `engine_studio_api` table (see `studioapi_StudioSetHeader`) and fixed slot
   0x8C.
2. The accessor must write exactly one writable global and read none; that store target is
   `pstudiohdr`.
3. The GV artifact reuses the accessor's `func_sig`; `gv_inst_offset/length/disp` point at
   the first base-referencing store. `gv_resolution_fields_via_mcp` supplies
   `gv_pic_addend` for register-relative sites.

## Pitfalls

- Slot 0x8C vs 0x90 is a one-slot separation; the GV is identified by the accessor's
  single-write shape, not by adjacency to `r_model`.
- Reference count is the sanity check: 27-32 functions per binary reference `pstudiohdr`.
- SvEngine Linux GOTOFF embeds var-GOT (no relocation) and needs the `gv_pic_addend` rebase.
- Cross-version evidence (2026-09-10): hl-10210 hw.dll `0x104D1BF8` / hw.so `0x3378C0`;
  hl-8684 `0x23B64E0`; hl-3248 `0x24849C0`; svencoop hw.dll `0x8DDD290`; cof-5936
  `0x248CFE4`. Addresses are evidence only.
