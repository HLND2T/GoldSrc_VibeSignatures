---
title: Draw_SpriteFrameGeneric locator
type: note
permalink: goldsrc-vibesignatures/locators/draw-spriteframegeneric
tags:
  - locator
  - engine
  - func
---

# Draw_SpriteFrameGeneric

## Symbol

- **Name**: `Draw_SpriteFrameGeneric`
- **Category**: `func`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-Draw_SpriteFrame-family.py`

## Availability

- Declared in 9 engine configs: cof-5936, hl-10210, hl-3248, hl-3266, hl-3329,
  hl-3647, hl-4554, hl-6153, hl-8684.
- Platforms: Windows + Linux (producer has no `platform` gating).
- Inlined / absent: not declared for svencoop-10257; the SvEngine counterpart is the
  separate Windows-only `Draw_SpriteFrameGeneric_SvEngine`, and on SvEngine Linux this
  renderer is inlined into `SPR_Draw*`.

## Predecessors

- None. Discovery starts from the diagnostic literal only.

## How it is located

1. `owners("Client.dll SPR_DrawGeneric error: invalid frame\n")` — exact-match literal
   owner(s). Unlike the HOLES / ADDITIVE literals this one has a **single** space after
   `error:`; the case is preserved verbatim.
2. Callees shared by all literal owners of the three families are dropped as helpers
   (`R_GetSpriteFrame`, `Con_DPrintf`, …).
3. The renderer is the unique remaining GENERIC-owner callee that calls the shared
   `Draw_Frame`, which the same walk resolves as the target reached from one candidate of
   every family.
4. Uniqueness is mandatory — otherwise `renderer not unique` and no writes for the family.

The address is inspected for `func_va` / `func_rva` / `func_size` / `func_sig` (with an
across-function-boundary retry). No byte pattern or old YAML participates.

## Pitfalls

- The GENERIC literal's spacing differs from the other two (`error: invalid` — one space).
  The anchor compares strings exactly, so this asymmetry is the discriminator, not a typo to
  normalize.
- The owner set is not assumed unique: a build may attach a literal to an unrelated function
  (the crosshair body was observed for HOLES), which is why the family uses a helper
  intersection and cross-family support rather than a single owner's callee set.
- Orphan (un-promoted) literal owners are dropped in this producer because `fn(x.frm)`
  returns None; the SvEngine variant has explicit contiguous-`is_code`-run recovery.
- The four family artifacts are written together after the whole address map resolves, so
  there is no partially written state.
