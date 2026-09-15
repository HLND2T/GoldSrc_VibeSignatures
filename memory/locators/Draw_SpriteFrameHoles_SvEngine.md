---
title: Draw_SpriteFrameHoles_SvEngine locator
type: note
permalink: goldsrc-vibesignatures/locators/draw-spriteframeholes-svengine
tags:
  - locator
  - engine
  - func
---

# Draw_SpriteFrameHoles_SvEngine

## Symbol

- **Name**: `Draw_SpriteFrameHoles_SvEngine`
- **Category**: `func`
- **Module**: engine (`hw.dll` — SvEngine Windows branch)
- **Producer**: `ida_preprocessor_scripts/find-Draw_SpriteFrame-family-svencoop.py`

## Availability

- Declared in 1 config: svencoop-10257.
- Platforms: Windows-only. The producer declares `platform: windows` and the svencoop
  symbol list marks this entry `platform: windows`.
- Inlined / absent: on **SvEngine Linux** the sprite-frame renderers are inlined into
  `SPR_Draw*` (the `SPR_Draw*` owners call `Draw_Frame` directly), so no standalone
  `Draw_SpriteFrameHoles_SvEngine` exists there. The `_SvEngine` suffix exists because the
  SvEngine bodies genuinely differ from the HL/CoF family.

## Predecessors

- None. The producer declares no `expected_input`.

## How it is located

1. `refs("SPR_DrawHoles: Invalid frame %d\n")` — the SvEngine diagnostic, exact string
   match. SvEngine keeps `engine/cl_draw.c SPR_DrawHoles` with this wording; it has no
   `Client.dll SPR_Draw*` literal and no `Draw_TransPic` / `Downloading %s` literal.
2. `family_union` turns those reference sites into a callee set. It prefers references
   **inside IDA-defined functions** and falls back to orphan references only when none of
   them is promoted, so a promoted sibling cannot pollute the family set.
3. For each reference site, the unit is the owning function, or — when IDA never promoted
   it — the **contiguous `is_code` run** around the xref. SvEngine units are
   padding-separated, so that run is exactly one function (no terminator scan is needed,
   unlike the draw-helpers producer). `call` / `jmp` targets that are function starts are
   the unit's callees.
4. `helper` = intersection of the three families' unions (`R_GetSpriteFrame`,
   `Con_DPrintf`, …); candidates = union − helper.
5. The renderer is the unique HOLES candidate that `call`s the shared `Draw_Frame`
   (`Draw_Frame` = the target reached from one candidate of all three families, and itself
   not a candidate).
6. Non-unique results emit `renderer not unique` (with `frames` and per-family `failed`
   lists) and write nothing for the family.

Emission: `_inspect_function_via_mcp` → `func_va` / `func_rva` / `func_size` / `func_sig`,
with an `allow_across_function_boundary` retry. No byte pattern participates.

## Pitfalls

- Windows-only by design. If someone re-enables it for Linux, the walk finds the `SPR_Draw*`
  owners but not a standalone renderer, because it is inlined there.
- The orphan recovery is the key SvEngine difference: half the `SPR_Draw*` diagnostics live
  in code IDA never promoted (`ida_funcs.get_func` returns None), and the
  contiguous-`is_code`-run rule is what makes the family resolvable. It depends on SvEngine
  units being padding-separated — do not reuse this rule on old HL builds, where several
  un-promoted functions share one gap and a terminator-bounded block is required instead.
- Nothing is written unless all four family symbols resolve (the address map is built before
  any YAML), so a failure here is all-or-nothing.
