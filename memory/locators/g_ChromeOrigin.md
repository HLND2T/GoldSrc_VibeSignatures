---
title: g_ChromeOrigin locator
type: note
permalink: goldsrc-vibesignatures/locators/g-chromeorigin
tags:
  - locator
  - engine
  - gv
---

# g_ChromeOrigin

## Symbol

- **Name**: `g_ChromeOrigin`
- **Category**: `gv`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-studioapi_SetChromeOrigin.py`,
  `ida_preprocessor_scripts/find-studioapi_SetChromeOrigin-svencoop.py`

## Availability

- Declared in 10 engine configs: hl-3248, hl-3266, hl-3329, hl-3647, hl-4554, hl-6153,
  hl-8684, hl-10210, cof-5936, svencoop-10257.
- Platforms: Windows + Linux.
- Inlined / absent: always present; emitted with `r_origin` by the same finder.

## Predecessors

- None. Produced by the same finder that produces `studioapi_SetChromeOrigin`.

## How it is located

1. Recover the `engine_studio_api` table and fixed slot 0x9C.
2. `cluster_bases` folds the accessor's writable refs into clusters; `VectorCopy(r_origin,
   g_ChromeOrigin)` produces one 12-byte read cluster and one 12-byte write cluster.
3. Shape gate `SLOT_SHAPE_COPY12`: the **write** base is `g_ChromeOrigin`.
4. Anchor at the first base-referencing store of the write cluster; `gv_sig` is the
   accessor's `func_sig`.

## Pitfalls

- Write side, not read side — do not swap with `r_origin`.
- SvEngine Linux stores through a `movss` GOTOFF site (`hw.dll` evidence:
  `0x1D929D0 -> 0x3F941D8 / 0x8DF3B30`; `hw.so 0x9FC10 -> flt_30F6EE0 / dword_D268C0`), so
  `gv_pic_addend` is required.
- Only 3-4 referencing functions per binary — the reference-count sanity check is weak here;
  rely on the read/write direction of the cluster shape instead.
- Cross-version evidence (2026-09-10): hl-10210 hw.dll `0x104EA0A0` / hw.so `0x320FC0`;
  hl-8684 `0x2358840`; hl-3248 `0x2433278`; svencoop hw.dll `0x8DF3B30`; cof-5936
  `0x242F340`. Addresses are evidence only.
