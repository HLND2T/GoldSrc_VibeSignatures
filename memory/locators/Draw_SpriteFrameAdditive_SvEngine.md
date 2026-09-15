---
title: Draw_SpriteFrameAdditive_SvEngine locator
type: note
permalink: goldsrc-vibesignatures/locators/draw-spriteframeadditive-svengine
tags:
  - locator
  - engine
  - func
---

# Draw_SpriteFrameAdditive_SvEngine

## Symbol

- **Name**: `Draw_SpriteFrameAdditive_SvEngine`
- **Category**: `func`
- **Module**: engine (`hw.dll` — SvEngine Windows branch)
- **Producer**: `ida_preprocessor_scripts/find-Draw_SpriteFrame-family-svencoop.py`

## Availability

- Declared in 1 config: svencoop-10257.
- Platforms: Windows-only (`platform: windows` on both the finder registration and the
  svencoop symbol declaration).
- Inlined / absent: inlined into `SPR_Draw*` on SvEngine Linux, so no standalone entry
  exists there. The `_SvEngine` suffix marks that the SvEngine body differs from the HL/CoF
  `Draw_SpriteFrameAdditive`.

## Predecessors

- None.

## How it is located

1. `refs("SPR_DrawAdditive: Invalid frame %d\n")` — exact SvEngine diagnostic string.
2. `family_union` converts each reference site into a unit: the IDA function when the site
   is inside one, otherwise the **contiguous `is_code` run** around the xref (the SvEngine
   recovery for diagnostics IDA never promoted). Promoted references take precedence over
   orphan references so a promoted sibling cannot pollute the set.
3. Helpers shared by all three families are removed by intersection; the remaining ADDITIVE
   candidates are filtered down to the single one that calls the shared `Draw_Frame`.
4. Non-unique → `renderer not unique` and no writes for the whole family.

Emission is `func_va` / `func_rva` / `func_size` / `func_sig` from
`_inspect_function_via_mcp` (with an across-function-boundary retry). No byte pattern or old
YAML participates.

## Pitfalls

- The diagnostic wording differs from HL/CoF (`SPR_DrawAdditive: Invalid frame %d\n` vs
  `Client.dll SPR_DrawAdditive error:  invalid frame\n`). Mixing the two literals across
  producers would fail silently because matching is exact.
- Depends on the contiguous-`is_code`-run recovery for un-promoted owners. That rule assumes
  SvEngine's padding-separated units; on old HL builds an un-promoted gap can hold several
  functions and the run would over-extend.
- Windows-only: on SvEngine Linux the renderer is inlined into `SPR_Draw*`.
- All four family results are resolved before any write, so failures are all-or-nothing.
