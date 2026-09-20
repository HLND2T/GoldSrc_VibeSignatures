---
title: CL_SetDevOverView locator
type: note
permalink: goldsrc-vibesignatures/locators/cl-setdevoverview
tags:
  - locator
  - engine
  - func
---

# CL_SetDevOverView

## Symbol

- **Name**: `CL_SetDevOverView`
- **Category**: `func`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-CL_SetDevOverView.py` (emits `gDevOverview` too)
- **Source**: `engine/cl_spectator.c`, `void CL_SetDevOverView( refdef_t *refdef )`. Confirmed by
  the retained `.symtab` of `hl-10210`, `hl-8684` and `svencoop-8948` `hw.so`.

## Availability

- All 11 engine configs (`hl-3248..hl-10210`, `cof-5936`, `svencoop-8948/10257`), every declared
  platform. BLOB tags analyse `hw.decrypt.dll`.

## Predecessors

- None. The finder has no `expected_input`.

## How it is located

Exact literal, one string instance and one owning function on every build:

```
" Overview: Zoom %.2f, Map Origin (%.2f, %.2f, %.2f), Z Min %.2f, Z Max %.2f, Rotated %i\n"
```

`exact_string_owner` in `_engine_private_globals_common` requires both counts to be 1 and fails
closed otherwise. The leading space is part of the literal.

## Pitfalls

- Do not anchor on the cvar name `"dev_overview"`: it is a registration string owned by
  `CL_InitSpectator`, not by this function, and on several builds it has no code xref at all.
- `CL_IsDevOverviewMode` and `CL_CalculateDevOverviewParameters` are siblings in the same
  translation unit; only the banner distinguishes the setter.
- Validation evidence (not consumed by the finder): hl-10210 W `0x101ad1c0` / L `0x12d9d0`,
  svencoop-8948 L `0x155bc0`, cof-5936 `0x1d3c0e3`.

## Relations

- relates_to [[gDevOverview]]
- relates_to [[r_refdef]]
