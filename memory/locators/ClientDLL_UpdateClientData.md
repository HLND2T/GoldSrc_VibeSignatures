---
title: ClientDLL_UpdateClientData locator
type: note
permalink: goldsrc-vibesignatures/locators/clientdll-updateclientdata
tags:
  - locator
  - engine
  - func
---

# ClientDLL_UpdateClientData

## Symbol

- **Name**: `ClientDLL_UpdateClientData`
- **Category**: `func`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-ClientDLL_UpdateClientData.py`
  (emits `ClientDLL_DemoUpdateClientData`, `cl_viewangles` and `scr_fov_value` in the same run)
- **Source**: `engine/cdll_int.c`, `void ClientDLL_UpdateClientData( void )`.

## Availability

- All 11 engine configs, every declared platform.

## Predecessors

- `cl_funcs`.

## How it is located

1. Collect every function referencing a `cl_funcs` member, dropping any that touches more than four
   members (that is the table registrar / `LoadInsecureClient`, not a consumer).
2. Exactly one member is shared by exactly **two** consumers: `pHudUpdateClientDataFunc`, `+0x10`
   on every validated build.
3. The two functions' shared globals are exactly one vec3 (`cl.viewangles`) plus one scalar
   (`scr_fov.value`).
4. Roles come from data flow, not an immediate: this function *reads* the view angles before the
   call (`VectorCopy( cl.viewangles, cdat.viewangles )`), the demo entry point only writes them.

## Pitfalls

- MetaHookSv's suggested discriminators (the immediates `5` for `ca_active` and `0x20`) are build
  dependent; the read/write asymmetry holds across MSVC SSE, GCC SSE and GCC x87 bodies.
- Write classification must come from the instruction's canonical `CF_CHG` feature, not from a
  mnemonic allow-list, otherwise `fstp ds:cl_viewangles` is misread as a read.
- Validation evidence: hl-10210 W `0x10197400` / L `0x159180`, svencoop-8948 L `0x17c330`.

## Relations

- relates_to [[ClientDLL_DemoUpdateClientData]]
- relates_to [[cl_viewangles]]
