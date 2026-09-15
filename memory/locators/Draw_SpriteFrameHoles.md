---
title: Draw_SpriteFrameHoles locator
type: note
permalink: goldsrc-vibesignatures/locators/draw-spriteframeholes
tags:
  - locator
  - engine
  - func
---

# Draw_SpriteFrameHoles

## Symbol

- **Name**: `Draw_SpriteFrameHoles`
- **Category**: `func`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-Draw_SpriteFrame-family.py`

## Availability

- Declared in 9 engine configs: cof-5936, hl-10210, hl-3248, hl-3266, hl-3329,
  hl-3647, hl-4554, hl-6153, hl-8684.
- Platforms: Windows + Linux (producer has no `platform` gating).
- Inlined / absent: not declared for svencoop-10257; the SvEngine counterpart is the
  separate symbol `Draw_SpriteFrameHoles_SvEngine` (Windows-only), and on SvEngine Linux
  this renderer is inlined into `SPR_Draw*`.

## Predecessors

- None. Discovery starts from the diagnostic literal only.

## How it is located

1. `owners("Client.dll SPR_DrawHoles error:  invalid frame\n")` — functions that reference
   the exact literal (note the two spaces after `error:`). Some builds have **two** owners
   (engine proxy plus a second copy); both are kept, and both call the same renderer, so the
   owner union is used.
2. Shared callees across the three families (`holes` / `additive` / `generic`) are removed
   as helpers — that intersection is `R_GetSpriteFrame`, `Con_DPrintf` and friends.
3. `Draw_SpriteFrameHoles` is the unique remaining HOLES-owner callee that calls the shared
   `Draw_Frame` (`find-Draw_SpriteFrame-family` resolves `Draw_Frame` in the same walk as
   the single callee reached from one candidate of all three families).
4. Exactly one hit is required. If the HOLES family ends with ≠1 candidate calling
   `Draw_Frame` the walk reports `renderer not unique` with the failing family's candidate
   list and writes nothing for the whole family.

The address is inspected for `func_va` / `func_rva` / `func_size` / `func_sig`, with an
`allow_across_function_boundary` retry. No byte pattern or old YAML participates.

## Pitfalls

- A build may attach the HOLES literal to an unrelated function (the crosshair body has been
  observed). The helper-intersection plus cross-family support rules exist to survive that;
  never trust a single owner's callee set.
- The double space in `...error:  invalid frame\n` is significant: the anchor uses exact
  string equality (`str(st) == text`), so a whitespace change silently drops the family and
  fails the walk.
- If the literal owner is not promoted to a function, `fn(x.frm)` returns None and that ref
  is dropped here (unlike the SvEngine producer, which recovers an orphan block).
- Each symbol of the family is emitted only after the whole address map resolved, so a
  failure here is all-or-nothing for the four symbols.
