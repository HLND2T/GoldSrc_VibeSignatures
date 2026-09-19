---
title: scr_fov_value locator
type: note
permalink: goldsrc-vibesignatures/locators/scr-fov-value
tags:
  - locator
  - engine
  - gv
---

# scr_fov_value

## Symbol

- **Name**: `scr_fov_value`
- **Category**: `gv`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-ClientDLL_UpdateClientData.py`
- **Source**: the `value` member of `cvar_t scr_fov`; `cdat.fov = scr_fov.value;` and the write-back
  `scr_fov.value = cdat.fov;` in `engine/cdll_int.c`. `hl-10210`, `hl-8684` and `svencoop-8948`
  Linux name the member `scr_fov_value` directly in `.symtab`.

## Availability

- All 11 engine configs, every declared platform.

## Predecessors

- `cl_funcs`.

## How it is located

The unique scalar (non-vec3) global the update pair share; see [[ClientDLL_UpdateClientData]].

## Pitfalls

- The artifact deliberately carries the **member** address, not `&scr_fov`. A consumer expecting the
  `cvar_t` base would be off by the `name` / `string` members.
- Validation evidence: hl-10210 W `0x10322f60` / L `0x2bee98`, svencoop-8948 L `0x33f0b8`.

## Relations

- relates_to [[cl_viewangles]]
