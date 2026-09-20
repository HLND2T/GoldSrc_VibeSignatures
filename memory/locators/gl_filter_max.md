---
title: gl_filter_max locator
type: note
permalink: goldsrc-vibesignatures/locators/gl-filter-max
tags:
  - locator
  - engine
  - gv
---

# gl_filter_max

## Symbol

- **Name**: `gl_filter_max`
- **Category**: `gv`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-Draw_TextureMode_f-globals.py`
- **Source**: `engine/gl_draw.c`, the `GL_TEXTURE_MAG_FILTER` value chosen by the
  `gl_texturemode` handler.

## Availability

- All 11 engine configs, every declared platform. Real symbol name is preserved
  in every non-stripped `.so`.

## Predecessors

- `Draw_TextureMode_f.{platform}.yaml`.

## How it is located

The higher-offset member of the adjacent `modes[i].minimize` / `modes[i].maximize`
store pair inside the handler. See [[gl_filter_min]] for the walk and for why the
two levels are never derived from each other.

## Pitfalls

- Do not compute it as `gl_filter_min ± 4`. The relation differs per build
  (`gl_filter_max = gl_filter_min + 4` on hl-10210 and svencoop-8948,
  `gl_filter_min - 0x10` on hl-8684, `gl_filter_max = gl_filter_min - 4` on
  cof-5936 and both SvEngine Windows builds).
- Validation evidence: hl-10210 L `0x2be9e0`, hl-8684 L `0x2d8040`,
  svencoop-8948 L `0x33ec40`, cof-5936 `0x1eb45ec`, hl-10210 W `0x1031e32c`.

## Relations

- relates_to [[Draw_TextureMode_f]]
- relates_to [[gl_filter_min]]
