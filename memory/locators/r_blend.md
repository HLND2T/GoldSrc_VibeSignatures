---
title: r_blend locator
type: note
permalink: goldsrc-vibesignatures/locators/r-blend
tags:
  - locator
  - engine
  - gv
---

# r_blend

## Symbol

- **Name**: `r_blend`
- **Category**: `gv`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-R_DrawSpriteModel-globals.py`
- **Source**: `engine/gl_rmain.c` — `float r_blend;` — the alpha the
  transparent-entity and sprite paths feed to `R_SpriteColor`/`qglColor4ub`.

## Availability

- All 11 engine configs, every declared platform.

## Predecessors

- `R_DrawSpriteModel.{platform}.yaml`.

## How it is located

`LLM_DECOMPILE` with `expected_result_sections: ["found_gv"]` against the
annotated [[R_DrawSpriteModel]] reference. In that body `r_blend` is the sprite
alpha: it is assigned `1.0` for `kRenderNormal` and multiplied by `255.0` for the
alpha argument.

## Pitfalls

- **The write form is not portable**, which is why a single operand form cannot
  be hardcoded: MSVC uses `movss r_blend, xmm0` (hl-10210 W) or
  `mov r_blend, 3F800000h` (cof-5936), GCC non-PIC uses
  `mov ds:r_blend, 3F800000h` (hl-10210/8684 L), SvEngine Windows emits `fst`
  of a `fld1`, and the early BLOB builds store an `ecx` that was set to
  `3F800000h` earlier (`mov dword_2788E14, ecx`).
- **SvEngine Linux reaches it only through a `.got` slot.** On svencoop-8948 the
  body loads the object address (`mov edi, ds:(r_blend_ptr - 33A000h)[ebx]`) and
  then reads/writes `[edi]`; there is no absolute operand naming `r_blend`. On
  svencoop-10257 it is a PIC `lea edi, (flt_7AE12CC - 2EE000h)[ebx]`. The shared
  `got_indirect_targets` / `gv_pic_addend` resolver handles both, and the
  artifact carries `gv_pic_addend: 0x2ee000` on 10257.
- Both SvEngine objects live in the `.data` section whose virtual size is
  ~120 MB, so their VAs are far above the code (`0x8e36310` on 10257 Windows,
  `0x7ae12cc` on 10257 Linux). That is not a misparse.
- Do not derive it from `gl_spriteblend` or the `255.0f` constant: those are
  separate `.rdata`/`.data` objects in the same body.
- Validation evidence: hl-10210 L `0x13cf808` (`.symtab`), hl-8684 L `0x1367260`
  (`.symtab`), svencoop-8948 L `0x7ac112c` (`.symtab`), hl-10210 W `0x111c50b4`,
  svencoop-10257 W `0x8e36310`, svencoop-10257 L `0x7ae12cc`, hl-3248 W
  `0x2788e14`.

## Relations

- relates_to [[R_DrawSpriteModel]]
- relates_to [[r_entorigin]]
