---
title: Draw_Frame locator
type: note
permalink: goldsrc-vibesignatures/locators/draw-frame
tags:
  - locator
  - engine
  - func
---

# Draw_Frame

## Symbol

- **Name**: `Draw_Frame`
- **Category**: `func`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-Draw_SpriteFrame-family.py` (HL/CoF, both
  platforms), `ida_preprocessor_scripts/find-Draw_SpriteFrame-family-svencoop.py`
  (svencoop-10257, `platform: windows`)

## Availability

- Declared in 10 engine configs: cof-5936, hl-10210, hl-3248, hl-3266, hl-3329,
  hl-3647, hl-4554, hl-6153, hl-8684, svencoop-10257.
- Platforms: Windows + Linux on the 9 HL/CoF configs; **Windows-only on svencoop-10257**
  (config declares `platform: windows`, and the svencoop producer is `platform: windows`).
- Inlined / absent: on SvEngine Linux the sprite-frame renderers are inlined into
  `SPR_Draw*` — the `SPR_Draw*` owners call `Draw_Frame` directly — so no standalone
  `Draw_Frame` entry exists there. On HL/CoF it is a real standalone function everywhere.

## Predecessors

- None. Neither producer declares `expected_input`; the sprite-frame family is discovered
  from literals only.

## How it is located

`Draw_Frame` is the **shared callee** of the three sprite-frame renderers, so it is found
by triangulation over the three `SPR_Draw*` diagnostic literals rather than by its own
signature.

HL/CoF producer:

1. `owners(text)` = functions referencing the exact literals
   `Client.dll SPR_DrawHoles error:  invalid frame\n`,
   `Client.dll SPR_DrawAdditive error:  invalid frame\n`,
   `Client.dll SPR_DrawGeneric error: invalid frame\n` (note the double space in HOLES and
   ADDITIVE, single space in GENERIC). A build may have **two owners** for HOLES (the engine
   proxy plus a second copy), so the owner set is a union.
2. `helper` = intersection of the call sets of all owners (`R_GetSpriteFrame`,
   `Con_DPrintf`, …). The intersection is computed across the union of all three families
   precisely because a build may attach a literal to an unrelated function.
3. `candidates[key]` = union of owner callees minus `helper`.
4. `support[target]` counts which families reach `target` from a candidate. `frames` =
   targets reached from a candidate of **all three** families and not themselves candidates.
5. Require exactly one frame and exactly one candidate per family calling it; otherwise the
   walk reports `renderer not unique` (with `frames` and the per-family `failed` lists) and
   nothing is written.

SvEngine producer: identical shape with the SvEngine literals
`SPR_DrawHoles: Invalid frame %d\n` / `...Additive...` / `...Generic...`. The differences are
(a) `family_union` resolves the literal refs directly and prefers references inside
IDA-defined functions, falling back to orphan refs only when none are promoted (so a
promoted sibling cannot pollute the set), and (b) an un-promoted literal site is recovered
as the **contiguous `is_code` run** around the xref — SvEngine units are padding-separated,
so that run is exactly one function.

The located address is inspected for `func_va` / `func_rva` / `func_size` / `func_sig` with
an across-function-boundary retry. No byte pattern participates in any variant.

## Pitfalls

- The literal-owner set is not trustworthy on its own: one build attaches the HOLES literal
  to an unrelated function (the crosshair body). That is why the anchor uses a helper
  intersection plus cross-family support instead of a single owner's callee set.
- SvEngine diagnostics may live in code IDA never promoted to a function
  (`ida_funcs.get_func` returns None); the contiguous `is_code` run is the recovery unit
  there, unlike the terminator-bounded block used by the draw-helpers producer.
- The `_SvEngine` renderer suffix exists because the SvEngine bodies genuinely differ from
  the HL family; do not read `Draw_Frame`'s artifact as implying the SvEngine renderers are
  separate functions on Linux — they are inlined.
- Both producers return False on any non-unique result; a partial write is impossible
  because the address map is resolved for all four symbols before any YAML is emitted.
