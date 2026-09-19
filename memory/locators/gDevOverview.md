---
title: gDevOverview locator
type: note
permalink: goldsrc-vibesignatures/locators/gdevoverview
tags:
  - locator
  - engine
  - gv
---

# gDevOverview

## Symbol

- **Name**: `gDevOverview`
- **Category**: `gv`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-CL_SetDevOverView.py`
- **Source**: `engine/cl_spectator.c`, `overviewInfo_t gDevOverview;` —
  `vec3_t origin; float z_min, z_max, zoom; qboolean rotated`, i.e. **seven** four-byte members.

## Availability

- All 11 engine configs, every declared platform.

## Predecessors

- `CL_SetDevOverView`, recovered inside the same finder run (no config `expected_input`).

## How it is located

The whole struct shape is the anchor. Inside `CL_SetDevOverView`, exactly one writable-data address
`a` has each of `a+0 +4 +8 +0xc +0x10 +0x14 +0x18` separately referenced by an instruction naming
only that global. The first such reference carrying a four-byte displacement becomes the signature
anchor, and `write_located_globals` derives `gv_pic_addend` / `gv_address_offset` as usual.

## Pitfalls

- Requiring fewer than seven members is not unique: the `+0/+4/+8` prefix alone also matches
  `refdef->vieworg`, which the same function writes.
- MetaHookSv's `Engine_FillAddress_RenderSceneVars2` disassembles 0x300 bytes, arms on a `PUSH 0x30`
  after instruction 100, collects up to six float loads and keeps the numerically lowest address.
  That heuristic does not survive the GCC x87 bodies here and is not used.
- IDA reports the *struct base* rather than the accessed member as the data xref of a PIC x87
  member access, so operand-derived addresses must take precedence over `DataRefsFrom`.
- Validation evidence: hl-10210 W `0x1124e660` / L `0xbc27f0`, svencoop-8948 L `0x15dcc30`.

## Relations

- relates_to [[CL_SetDevOverView]]
