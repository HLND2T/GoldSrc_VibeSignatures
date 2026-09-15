---
title: Draw_SpriteFrameAdditive locator
type: note
permalink: goldsrc-vibesignatures/locators/draw-spriteframeadditive
tags:
  - locator
  - engine
  - func
---

# Draw_SpriteFrameAdditive

## Symbol

- **Name**: `Draw_SpriteFrameAdditive`
- **Category**: `func`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-Draw_SpriteFrame-family.py`

## Availability

- Declared in 9 engine configs: cof-5936, hl-10210, hl-3248, hl-3266, hl-3329,
  hl-3647, hl-4554, hl-6153, hl-8684.
- Platforms: Windows + Linux (producer has no `platform` gating).
- Inlined / absent: not declared for svencoop-10257; the SvEngine counterpart is the
  separate Windows-only `Draw_SpriteFrameAdditive_SvEngine`, and on SvEngine Linux this
  renderer is inlined into `SPR_Draw*`.

## Predecessors

- None. Discovery starts from the diagnostic literal only.

## How it is located

1. `owners("Client.dll SPR_DrawAdditive error:  invalid frame\n")` — functions referencing
   that exact literal (two spaces after `error:`).
2. Callees shared by every literal owner across all three families (`R_GetSpriteFrame`,
   `Con_DPrintf`, …) are removed as helpers.
3. Among the remaining ADDITIVE-owner callees, the renderer is the one that calls the shared
   `Draw_Frame` — `Draw_Frame` itself is resolved in the same walk as the single callee
   reached from a candidate of each of the three families.
4. Uniqueness is mandatory. A family with ≠1 candidate calling `Draw_Frame` makes the walk
   emit `renderer not unique` plus the failing candidate lists and write nothing at all.

Emission goes through `_inspect_function_via_mcp` (`func_va` / `func_rva` / `func_size` /
`func_sig`) with an `allow_across_function_boundary` retry. No byte pattern participates.

## Pitfalls

- Exact string equality is used (`str(st) == text`), including the double space after
  `error:`; a whitespace change silently drops the family.
- The owner set can contain an unrelated function that merely embedded the literal, so the
  helper intersection and the "calls the shared `Draw_Frame`" support rule are load-bearing,
  not cosmetic.
- The literal owner must be an IDA-defined function here: `fn(x.frm)` returning None drops
  the reference. The SvEngine producer has its own orphan-block recovery.
- All four family symbols are emitted only after the address map resolves, so this symbol
  never exists as a partially written artifact.
