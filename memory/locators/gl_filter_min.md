---
title: gl_filter_min locator
type: note
permalink: goldsrc-vibesignatures/locators/gl-filter-min
tags:
  - locator
  - engine
  - gv
---

# gl_filter_min

## Symbol

- **Name**: `gl_filter_min`
- **Category**: `gv`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-Draw_TextureMode_f-globals.py`
- **Source**: `engine/gl_draw.c`, the `GL_TEXTURE_MIN_FILTER` value chosen by the
  `gl_texturemode` handler.

## Availability

- All 11 engine configs, every declared platform. Real symbol name is preserved
  in every non-stripped `.so` (hl-10210, hl-8684, svencoop-8948).

## Predecessors

- `Draw_TextureMode_f.{platform}.yaml`.

## How it is located

The handler writes both filter levels from one `modes` table:

    gl_filter_min = modes[i].minimize;   // table entry + 4
    gl_filter_max = modes[i].maximize;   // table entry + 8

The walk takes the unique adjacent store pair whose source registers were loaded
from one shared base with a four-byte displacement delta; the lower-offset load
feeds `gl_filter_min`. Store order follows table offset on every validated build
(CoF MSVC, HL25 MSVC, SvEngine MSVC, HL25 GCC, SvEngine GCC).

The walk decodes the load's x86 ModRM/SIB base, index, scale and displacement,
and compares register definitions inside one basic block. CoF independently
reloads and multiplies the same frame-local table index into two registers;
that equivalence is proven from the stack read and IMUL, not register names.
Intervening register clobbers, calls, potential frame writes and block changes
invalidate the corresponding proof. Equal displacement deltas alone are insufficient.

## Pitfalls

- **`gl_filter_min` and `gl_filter_max` are not interchangeable by offset.** They
  are adjacent with `gl_filter_max` first on hl-10210 and svencoop-8948, adjacent
  with `gl_filter_min` first on cof-5936 and both SvEngine Windows builds, and
  `0x10` apart on hl-8684. Each is read from its own store.
- A direct locator is used instead of an LLM predecessor because the classic,
  HL25 and SvEngine handler bodies differ substantially while `{gamever}`
  reference resolution only falls back to hl-10210 — one reference per legacy
  family would be required.
- The SvEngine Windows handler is not a function in the IDB; the finder calls
  `ensure_function_defined` before the walk. See
  [[SvEngine Windows IDBs leave GL_TextureMode_f outside any function]].
- SvEngine Linux stores are GOT-relative (`mov %edx,0x4c44(%ebx)`), so the
  artifact carries `gv_pic_addend`; MSVC stores are absolute.
- Validation evidence: hl-10210 L `0x2be9e4`, hl-8684 L `0x2d8050`,
  svencoop-8948 L `0x33ec44`, cof-5936 `0x1eb45e8`, hl-10210 W `0x1031e328`.

## Relations

- relates_to [[Draw_TextureMode_f]]
- relates_to [[gl_filter_max]]
