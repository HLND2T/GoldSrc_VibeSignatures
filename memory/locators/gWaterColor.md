---
title: gWaterColor locator
type: note
permalink: goldsrc-vibesignatures/locators/gwatercolor
tags:
  - locator
  - engine
  - gv
---

# gWaterColor

## Symbol

- **Name**: `gWaterColor`
- **Category**: `gv`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-R_DrawWorld-gWaterColor.py`
- **Source**: `engine/gl_rsurf.c` declares `extern colorVec gWaterColor;` and `R_DrawWorld` copies
  `ent.curstate.rendercolor.r/g/b = gWaterColor.r/g/b;`

## Availability

- All 11 engine configs, every declared platform.

## Predecessors

- `R_DrawWorld`.

## How it is located

The unique writable global whose `+0`/`+4`/`+8` dwords are each read **and** whose low bytes are
stored into three *consecutive* bytes of one `cl_entity_t`. The destination object is tracked by
register provenance (stack local vs. loaded pointer) so the three stores are proven to target the
same object.

## Pitfalls

- The dword-triple alone is not unique: `r_refdef.vieworg` and `modelorg` are also three adjacent
  floats copied in the same prologue. The byte-narrowing store is the discriminator.
- CoF-5936 stores through the `currententity` pointer, reloading it into a different register for
  each byte; a rule assuming `[ebp+disp]` / `[esp+disp]` stack stores misses it entirely.
- MetaHookSv keeps `GWATERCOLOR_SIG` / `GWATERCOLOR_SIG_HL25` byte patterns and derives
  `cshift_water = gWaterColor + 12`. That relation does **not** hold on these builds — measured
  `+0x10` on Windows and `+0x44` on Linux — and `cshift_water` has its own semantic locator.
- Validation evidence: hl-10210 W `0x109b3bf0` / L `0xf9612c`, svencoop-8948 L `0x34d806c`,
  cof-5936 `0x27fc2d0`.

## Relations

- relates_to [[r_refdef]]
