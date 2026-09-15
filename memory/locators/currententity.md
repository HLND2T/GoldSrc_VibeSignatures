---
title: currententity locator
type: note
permalink: goldsrc-vibesignatures/locators/currententity
tags:
  - locator
  - engine
  - gv
---

# currententity

## Symbol

- **Name**: `currententity`
- **Category**: `gv`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-studioapi_GetCurrentEntity.py`,
  `ida_preprocessor_scripts/find-studioapi_GetCurrentEntity-svencoop.py`

## Availability

- Declared in 10 engine configs: hl-3248, hl-3266, hl-3329, hl-3647, hl-4554, hl-6153,
  hl-8684, hl-10210, cof-5936, svencoop-10257.
- Platforms: Windows + Linux.
- Inlined / absent: always present as a mapped global; it is emitted together with its
  accessor, never standalone.

## Predecessors

- None. Produced by the same finder that produces `studioapi_GetCurrentEntity`; no
  `expected_input`.

## How it is located

1. The `engine_studio_api` table is recovered first (see `studioapi_GetCurrentEntity`),
   then fixed slot 0x18 names the accessor.
2. The accessor body must read **exactly one** writable global and write none. That single
   read target is `currententity`.
3. The GV artifact reuses the accessor's `func_sig` as `gv_sig` /
   `gv_inst_offset`/`gv_inst_length`/`gv_inst_disp` point at the first base-referencing
   instruction of the read cluster (direct-locator exception, `find-cl_resourcesonhand`
   precedent). `gv_resolution_fields_via_mcp` adds `gv_pic_addend` for register-relative
   (GOTOFF) sites.

## Pitfalls

- Do not confuse with `DM_PlayerState`: `currententity` is dereferenced at `+0x0B94` inside
  `studioapi_SetupPlayerModel`, while the DM array element model field is at `+0x208`.
- SvEngine Linux loads it through an eax-anchored GOTOFF `lea`; the embedded displacement is
  var-GOT, so it needs `gv_pic_addend` (GOT RVA) to resolve at runtime.
- Cross-version evidence (2026-09-10 probes): hl-10210 hw.dll `0x10DC5618` / hw.so `0xF7D930`;
  hl-8684 hw.dll `0x2BC98FC`; hl-3248 `0x2C2023C`; svencoop hw.dll `0x3F94150`; cof-5936
  `0x2C0E4BC`. Addresses are evidence only.
