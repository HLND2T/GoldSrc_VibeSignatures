---
title: r_entorigin locator
type: note
permalink: goldsrc-vibesignatures/locators/r-entorigin
tags:
  - locator
  - engine
  - gv
---

# r_entorigin

## Symbol

- **Name**: `r_entorigin`
- **Category**: `gv`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-R_DrawSpriteModel-decompiles.py`
- **Source**: `engine/gl_rmain.c` — `vec3_t modelorg, r_entorigin;` — the origin of
  the entity currently being rendered, consumed by the sprite and glow paths.

## Availability

- All 11 engine configs, every declared platform.

## Predecessors

- `R_DrawSpriteModel.{platform}.yaml`.

## How it is located

`LLM_DECOMPILE` with `expected_result_sections: ["found_gv"]` against the
annotated [[R_DrawSpriteModel]] reference. In that body `r_entorigin` is the vec3
every sprite quad corner is offset from: it is the first `VectorMA` operand in
the four-corner emission, so the same function that owns [[r_blend]] also names
this global on every family and platform.

## Pitfalls

- **Producer history.** PR #166 recovered this global from
  `R_DrawTEntitiesOnList`, which copies `currententity->origin` into it while the
  transparent list is walked. That copy only exists on the non-SvEngine families,
  so the symbol was declared in the two svencoop configs but had no producer
  there. The sprite renderer reads the global unconditionally, so the producer
  moved to `find-R_DrawSpriteModel-decompiles` and the SvEngine gap closed. Expected
  values were preserved exactly: hl-10210 Linux is still `0xf7d300`.
- **Access form is not portable.** MSVC emits `push offset <gv>` (four times, the
  four `VectorMA` calls); GCC non-PIC emits `mov [esp+..], offset r_entorigin`;
  both SvEngine builds hoist the address once with a PIC
  `lea eax, (r_entorigin - GOT)[ebx]` and reuse it. The shared resolver handles
  all three, including the `gv_pic_addend` the PIC form carries.
- `r_entorigin` has no fixed relation to `modelorg` or `r_origin`: cof-5936 puts
  it `+0x1e0` above `modelorg`, hl-10210 `-0x6e0` below, and on svencoop-10257 it
  is `modelorg - 0xc`. Never derive one from the other.
- On both SvEngine builds the object sits in the ~120 MB virtual `.data` section,
  far above the code.
- Validation evidence: hl-10210 W `0x10dc5620` / L `0xf7d300` (`.symtab`),
  hl-8684 L `0xf25300` (`.symtab`), cof-5936 W `0x2c0e4a0`, hl-3248/3266 W
  `0x2c20220`, hl-3329 W `0x2becb40`, hl-3647 W `0x2beb9c0`, hl-4554 W
  `0x2b957c0`, hl-6153 W `0x2bc63e0`, svencoop-8948 L `0x30d6ddc` (`.symtab`),
  svencoop-10257 W `0x3f94144` / L `0x30f6f7c`.

## Relations

- relates_to [[R_DrawSpriteModel]]
- relates_to [[r_blend]]
- relates_to [[modelorg]]
