---
title: ClientDLL_DemoUpdateClientData locator
type: note
permalink: goldsrc-vibesignatures/locators/clientdll-demoupdateclientdata
tags:
  - locator
  - engine
  - func
---

# ClientDLL_DemoUpdateClientData

## Symbol

- **Name**: `ClientDLL_DemoUpdateClientData`
- **Category**: `func`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-ClientDLL_UpdateClientData.py`
- **Source**: `engine/cdll_int.c`,
  `void ClientDLL_DemoUpdateClientData( client_data_t *cdat )`, called from `cl_demo.c`.

## Availability

- All 11 engine configs, every declared platform.

## Predecessors

- `cl_funcs`. See [[ClientDLL_UpdateClientData]] for the shared walk.

## How it is located

It is the member-pair partner that *only writes* `cl.viewangles` — it receives `cdat` from the demo
reader instead of filling it from engine state. Its body is small (0x48-0x83 bytes) and stable, so
it also supplies the signature anchor for both emitted globals.

## Pitfalls

- Do not identify it by size or by "the smaller of the pair": on the older Windows builds the two
  bodies are 0x10e and 0x5b bytes, but that ordering is incidental.
- Validation evidence: hl-10210 W `0x10196cf0` / L `0x1592d0`, svencoop-8948 L `0x17c4e0`
  (`_Z30ClientDLL_DemoUpdateClientDataP13client_data_s`).

## Relations

- relates_to [[ClientDLL_UpdateClientData]]
