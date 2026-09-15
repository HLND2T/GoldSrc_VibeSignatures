---
title: r_origin locator
type: note
permalink: goldsrc-vibesignatures/locators/r-origin
tags:
  - locator
  - engine
  - gv
---

# r_origin

## Symbol

- **Name**: `r_origin`
- **Category**: `gv`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-studioapi_SetChromeOrigin.py`,
  `ida_preprocessor_scripts/find-studioapi_SetChromeOrigin-svencoop.py`

## Availability

- Declared in 10 engine configs: hl-3248, hl-3266, hl-3329, hl-3647, hl-4554, hl-6153,
  hl-8684, hl-10210, cof-5936, svencoop-10257.
- Platforms: Windows + Linux.
- Inlined / absent: always present; emitted with `g_ChromeOrigin` by the same finder.

## Predecessors

- None. Produced by the same finder that produces `studioapi_SetChromeOrigin`.

## How it is located

1. Recover the `engine_studio_api` table and fixed slot 0x9C.
2. In the accessor body, group writable-data refs into clusters (`cluster_bases`, values
   within 8 bytes fold together). `VectorCopy(r_origin, g_ChromeOrigin)` yields exactly one
   read cluster (12 bytes) and one write cluster (12 bytes).
3. Shape gate `SLOT_SHAPE_COPY12`: one read base, one write base, distinct. The **read** base
   is `r_origin`.
4. Anchor the GV at the first base-referencing instruction of the read cluster; `gv_sig` is
   the accessor's `func_sig`.

## Pitfalls

- `r_origin` is the read side; `g_ChromeOrigin` is the write side. Getting the direction
  backwards swaps the two artifacts.
- SvEngine Linux reads it via a GOTOFF `lea` cluster base, so `gv_pic_addend` (GOT RVA) is
  required for the runtime address.
- Reference count ~20-25 functions per binary.
- Cross-version evidence (2026-09-10): hl-10210 hw.dll `0x10DC5578` / hw.so `0xF7D760`;
  hl-8684 `0x2BC98F0`; hl-3248 `0x2C20230`; svencoop hw.dll `0x3F941D8`; cof-5936
  `0x2C0E4B0`. Addresses are evidence only.
