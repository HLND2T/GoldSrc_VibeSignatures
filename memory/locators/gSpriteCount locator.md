---
title: gSpriteCount locator
type: note
permalink: goldsrc-vibesignatures/locators/g-sprite-count-locator
tags:
- locator
- engine
- gv
---

# gSpriteCount

## Symbol

- **Name**: `gSpriteCount`
- **Category**: `gv`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-Mod_UnloadSpriteTextures.py`
- **Source type**: signed `int`; it is the sprite-list capacity/loop bound and is initialized to 256.

## Availability

- Declared in all 11 engine configs: cof-5936, hl-3248, hl-3266, hl-3329, hl-3647, hl-4554, hl-6153, hl-8684, hl-10210, svencoop-8948, svencoop-10257.
- Windows on all 11 configs; Linux on hl-8684, hl-10210, svencoop-8948, and svencoop-10257.
- Not applicable to cstrike/czero/czeror because those configs have no engine module.

## Predecessors

- No artifact predecessor. The producer discovers `[[SPR_Shutdown locator]]`, `[[Mod_UnloadSpriteTextures locator]]`, and both sprite globals in one current-IDB pass.

## How it is located

1. Recover the two sprite globals by intersecting `SPR_Load` accesses with `SPR_Shutdown` stores.
2. Search only functions referenced by both slots for the initializer shape.
3. The unique slot receiving 256 is `gSpriteCount`; the same function must reference the other slot and establish a 12-byte-entry allocation (`0xC00` directly or count multiplied by 12).
4. Emit a GV artifact using the verified `SPR_Shutdown` signature, the selected count access, and `gv_resolution_fields_via_mcp`.

## Pitfalls

- `gSpriteCount` is capacity/loop bound, not the number of currently loaded sprites.
- Do not classify it by address order relative to `gSpriteList`; that order differs across platforms.
- CoF computes the allocation size through `gSpriteCount * 12` rather than a literal `0xC00`.
- SvEngine Linux uses EBX/GOTOFF and requires `gv_pic_addend`; classic/HL25 Linux uses relocated absolute operands.