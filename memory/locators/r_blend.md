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
- **Producer**: `ida_preprocessor_scripts/find-studioapi_StudioSetRenderamt.py`
- **Source**: `engine/gl_rmain.c` — `float r_blend;` — the alpha the
  transparent-entity and sprite paths feed to `R_SpriteColor`/`qglColor4ub`.

## Availability

- All 11 engine configs, every declared platform.

## Predecessors

- None. It is emitted together with the `studioapi_StudioSetRenderamt` entry by
  the same finder, so there is no separate artifact to load.

## How it is located

The `studioapi_StudioSetRenderamt` accessor body is recovered structurally from
the studio-interface table (slot `0xAC`), then `r_blend` is the function's
**sole writable-data store target** — `SLOT_SHAPE_WRITE_ALLOW_READS`.

`engine/r_studio.c` stores the render amount and then converts the blended value
back into the sprite alpha:

```c
currententity->curstate.renderamt = iRenderamt;
r_blend = CL_FxBlend( currententity ) / 255.0f;
```

`renderamt` lands in a pointer-relative field (`mov [ecx+2FCh], eax`), so it is
not a global reference; the only absolute writable-data store left is `r_blend`.

## Pitfalls

- **The accessor also reads globals, so every read-free write shape rejects it.**
  `currententity` is read before the call (`mov ecx, currententity` and
  `push currententity`), and the x87 builds read `r_blend` back between its two
  stores. `SLOT_SHAPE_WRITE` / `SLOT_SHAPE_WRITE_NO_GV` require an empty read
  list and `SLOT_SHAPE_WRITE_PAIR` requires exactly two ordered stores, so
  `SLOT_SHAPE_WRITE_ALLOW_READS` is the shape that fits.
- **Do not derive it from the `1/255` constant.** On hl-10210 W that is
  `qword_102B9348` in `.rdata` (read-only double, shared by 8 functions), so it
  can never land in `write_bases`; it is also not function-private and must not
  be used as an anchor.
- **The accessor has no symbol in the IDB.** It is `sub_101F3CC0` on hl-10210 W;
  slot `0xAC` is the only way in, exactly as for the sibling studio accessors.
- **The store form varies by code generation**, which is why the shape gates on
  "sole write target" rather than an operand pattern: MSVC/SSE stores
  `movss r_blend, xmm0` (hl-10210 W, `F3 0F 11 05`), the x87 builds end in
  `fstp dword ptr ds:r_blend` (`D9 1D`), and cof-5936 reaches the same object
  with `fst` (`D9 15`) before multiplying by the reciprocal.
- **`R_DrawSpriteModel` is no longer the predecessor.** It still writes `r_blend`
  (`0x10242D39` on hl-10210 W) and remains one of six writers alongside
  `R_DrawTEntitiesOnList` and `R_RenderScene`, but the sprite renderer now only
  carries [[r_entorigin]].
- **SvEngine Linux stores through an address-taken register.** On
  svencoop-8948/10257 `hw.so` the store is indirect: `lea eax,
  (r_blend - GOT)[ebx]` (`0xA0A4D` on 10257, offset `+0x2D`) then
  `fstp dword ptr [eax]` (`0xA0A63`, `o_phrase`, no IDA data xref). The shared
  collector tracks the LEA's global address through register copies and
  recognizes the real indirect store. The artifact retains the LEA as its
  encodable disp32 reference and carries `gv_inst_offset: 0x2D`,
  `gv_inst_length: 0x6`, `gv_inst_disp: 0x2`, `gv_pic_addend: 0x2ee000`.
- **Update register state even without a disp32 operand.** The old early
  `continue` skipped `mov eax,[eax]`, leaving the address of `currententity`
  tracked as though it were the pointer's runtime value. The following
  `mov [eax+2FCh],edx` then synthesized a false writable global. Every decoded
  instruction now participates in state updates; dereferences, register
  overwrites (including partial registers) and call-clobbered registers lose
  their tracked base. Read-only instructions preserve it. The shape requires
  a real non-derived write; the former read-target fallback has been removed.
- svencoop-10257 `hw.so` has **no** `.symtab` name for either `r_blend` or
  `currententity` (unlike hl-10210, hl-8684 and svencoop-8948, whose `.so`s
  export both), so that binary can only be validated structurally.
- Validation evidence (VAs): hl-10210 W `0x111c50b4`, hl-3248 W `0x2788e14`,
  hl-10210 L `0x13cf808` (`.symtab`), hl-8684 L `0x1367260` (`.symtab`),
  svencoop-8948 L `0x7ac112c` (`.symtab`), svencoop-10257 W `0x8e36310`,
  svencoop-10257 L `0x7ae12cc`.
- Shared-tracking regression validation (2026-09-24): fresh isolated IDA runs
  covered 225 studio-related finder nodes across all 11 configs / 15 binaries.
  All succeeded. Of 495 YAML outputs, 480 matched the baseline mappings
  (including GetTimes globals); all 15 `r_blend` VAs matched, with only the
  planned sprite-to-studio signature-anchor migration differing. Unit coverage
  exercises no-disp32 dereferences, register copies, partial writes, volatile
  call clobbers and indirect stores retaining the original LEA reference.
  The full source test suite ran 1141 tests, `OK (skipped=9)`.

## Relations

- relates_to [[studioapi_StudioSetRenderamt]]
- relates_to [[r_entorigin]]
