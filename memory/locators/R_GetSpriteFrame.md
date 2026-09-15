---
title: R_GetSpriteFrame locator
type: note
permalink: goldsrc-vibesignatures/locators/r-getspriteframe
tags:
  - locator
  - engine
  - func
---

# R_GetSpriteFrame

## Symbol

- **Name**: `R_GetSpriteFrame`
- **Category**: `func`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-R_GetSpriteFrame.py`

## Availability

- Declared in 10 engine configs: cof-5936, hl-10210, hl-3248, hl-3266, hl-3329, hl-3647, hl-4554, hl-6153, hl-8684, svencoop-10257.
- Platforms: Windows + Linux (no `platform` gate). Linux engine modules exist only for hl-10210, hl-8684 and svencoop-10257.
- Inlined / absent: not observed inlined; the frame resolver is a standalone function in every build.
- Not applicable to cstrike/czero/czeror (no engine module in this repo).

## Predecessors

- None. `find-R_GetSpriteFrame` has no `expected_input`.

## How it is located

`preprocess_common_skill` with a single exact string xref:

- `FULLMATCH:Sprite:  no pSprite!!!\n` — the `engine/cl_tent.c` diagnostic printed when the frame lookup is asked to resolve a frame without a sprite. Note the **two spaces** after `Sprite:`, which is part of the literal and must be reproduced exactly.

No byte signature participates in discovery. `_inspect_function_via_mcp` emits `func_name / func_sig / func_va / func_rva / func_size`.

## Pitfalls

- The literal contains doubled whitespace (`Sprite:` + two spaces) — a "cleaned up" needle silently never matches.
- The same family of `FULLMATCH` anchors reads the shared IDB string list, so short-literal pollution applies; there is no structural fallback in this finder.
- Blob engines (hl-3248..hl-3647) are Windows-only and run against `hw.decrypt.dll`.
