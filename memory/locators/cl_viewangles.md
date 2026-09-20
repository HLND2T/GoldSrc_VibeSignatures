---
title: cl_viewangles locator
type: note
permalink: goldsrc-vibesignatures/locators/cl-viewangles
tags:
  - locator
  - engine
  - gv
---

# cl_viewangles

## Symbol

- **Name**: `cl_viewangles`
- **Category**: `gv`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-ClientDLL_UpdateClientData.py`
- **Source**: the `viewangles` vec3 member of the engine's `client_state_t cl`
  (`engine/cdll_int.c` uses `VectorCopy( cl.viewangles, cdat.viewangles )`).

## Availability

- All 11 engine configs, every declared platform.

## Predecessors

- `cl_funcs`.

## How it is located

The unique `{x, x+4, x+8}` triple among the globals the update pair share; see
[[ClientDLL_UpdateClientData]]. The signature anchors on the demo entry point's reference.

## Pitfalls

- The artifact names the `cl.viewangles` *member*, not the `cl` struct base.
- On SvEngine Linux the access is `movss [edi+0x2423E4], xmm0` against a GOT-loaded `cl` base, so
  the emitted artifact carries a `gv_pic_addend` exactly like the existing `cl_light_level`.
- Validation evidence: hl-10210 W `0x11282b44` / L `0xc5a664`, svencoop-8948 L `0x1830c84`.

## Relations

- relates_to [[scr_fov_value]]
