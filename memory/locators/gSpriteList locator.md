---
title: gSpriteList locator
type: note
permalink: goldsrc-vibesignatures/locators/g-sprite-list-locator
tags:
- locator
- engine
- gv
---

# gSpriteList

## Symbol

- **Name**: `gSpriteList`
- **Category**: `gv`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-Mod_UnloadSpriteTextures.py`
- **Source type**: `SPRITELIST *`, where each entry is 12 bytes (`model_t *pSprite`, `char *pName`, `int frameCount`).

## Availability

- Declared in all 11 engine configs: cof-5936, hl-3248, hl-3266, hl-3329, hl-3647, hl-4554, hl-6153, hl-8684, hl-10210, svencoop-8948, svencoop-10257.
- Windows on all 11 configs; Linux on hl-8684, hl-10210, svencoop-8948, and svencoop-10257.
- Not applicable to cstrike/czero/czeror because those configs have no engine module.

## Predecessors

- No artifact predecessor. The producer discovers `[[SPR_Shutdown locator]]`, `[[Mod_UnloadSpriteTextures locator]]`, and both sprite globals in one current-IDB pass.

## How it is located

1. Anchor `SPR_Load` with the full allocation-error literal.
2. Locate `SPR_Shutdown` through the unique `SPR_Shutdown -> Mod_UnloadSpriteTextures` graph.
3. Intersect writable globals referenced by `SPR_Load` with globals stored by `SPR_Shutdown`; exactly two must remain.
4. Find the unique common owner that initializes the count to 256 and allocates either `0xC00` bytes or `256 * 12`. The slot not receiving 256 is `gSpriteList`.
5. Emit a GV artifact using the verified `SPR_Shutdown` signature, selected access offset, and operand resolution metadata.

## Pitfalls

- Do not infer identity from adjacency: Windows commonly lays out list then count, while HL25/SvEngine Linux lay out count then list.
- HL8684/HL25 Linux use relocated absolute operands. SvEngine Linux uses EBX/GOTOFF and requires `gv_pic_addend`.
- The raw SvEngine displacement is not a VA; runtime resolution adds the emitted PIC addend and module base.
- The global is a pointer slot, not the allocated array itself.