---
title: Mod_UnloadSpriteTextures locator
type: note
permalink: goldsrc-vibesignatures/locators/mod-unloadspritetextures
tags:
  - locator
  - engine
  - func
---

# Mod_UnloadSpriteTextures

## Symbol

- **Name**: `Mod_UnloadSpriteTextures`
- **Category**: `func`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-Mod_UnloadSpriteTextures.py`

## Availability
- Declared in all 11 engine configs: cof-5936, hl-3248, hl-3266, hl-3329, hl-3647, hl-4554, hl-6153, hl-8684, hl-10210, svencoop-8948, svencoop-10257.
- Platforms: every platform shipped by those engine modules — Windows for all 11 configs, plus Linux for hl-8684, hl-10210, svencoop-8948, and svencoop-10257.
- `SPR_Shutdown` and `Mod_UnloadSpriteTextures` remain independent functions in every validated target. HL25/SvEngine inline a copy of the broader `ClientDLL_Shutdown` flow into `ClientDLL_Init`, but that does not inline either sprite function.
- Not applicable to cstrike/czero/czeror because those configs have no engine module.
## Predecessors
- No artifact predecessor. Discovery starts from the exact `SPR_Load` allocation-error literal and the `%s_%i` sprite-texture-name literal in the current IDB.
- The same producer emits `[[SPR_Shutdown locator]]`, `[[gSpriteList locator]]`, and `[[gSpriteCount locator]]`.
## How it is located
The producer performs one deterministic, fail-closed graph/data-flow walk; no prior artifact or byte signature participates in discovery:

1. Find the unique owner of the case-insensitive exact literal `cannot allocate more than %d HUD sprites\n`. Orphan PE code is promoted to a function only from the bounded gap immediately after the previous function. This owner is `SPR_Load`.
2. Find owners of `%s_%i` and their direct callers. Keep functions using member displacements `model_t::type +0x44`, `needload +0x40`, `cache.data +0x184`, and `msprite_t::numframes +0x0C`.
3. Normalize ELF PLT/internal thunks. Keep the unique candidate whose sole semantic caller has one call to it, two calls to the same free helper, and a 12-byte `SPRITELIST` loop. The callee is `Mod_UnloadSpriteTextures`; the caller is `SPR_Shutdown`.
4. Intersect writable globals used by `SPR_Load` with globals stored by `SPR_Shutdown`. Exactly two must survive. Classify `gSpriteCount` through the unique common owner that stores 256 and allocates either literal `0xC00` or `256 * 12`; the other slot is `gSpriteList`.
5. Generate unique function signatures after discovery. The two GV artifacts reuse the verified `SPR_Shutdown` signature plus the selected access-instruction offset and `gv_resolution_fields_via_mcp` metadata.

The final fresh-artifact validation covered all 15 configured engine/platform targets with 15 successes, zero failures, and zero skips.
## Pitfalls
- The allocation diagnostic starts with lowercase `cannot` in classic/HL25 builds and uppercase `Cannot` in SvEngine; matching is full-string and case-insensitive only for that first-letter family difference.
- Older classic builds keep `Mod_SpriteTextureName` out of line, while newer builds inline it. Therefore `%s_%i` may belong to the target or to its helper; member-offset and shutdown-caller gates provide the identity.
- HL8684 Linux has another `%s_%i` context in `Mod_LoadAliasModel`; the unique shutdown caller/free/stride graph rejects it.
- Windows import thunks such as `free` may have no internal body. They retain the thunk entry for semantic call counting. ELF PLT thunks are resolved to their internal bodies.
- HL8684/HL25 Linux use relocated absolute operands; SvEngine Linux uses EBX/GOTOFF. The latter emits `gv_pic_addend`; never treat the raw displacement as a VA.
- CoF computes the list allocation as `gSpriteCount * 12` instead of embedding `0xC00`.
- Missing/ambiguous strings, function owners, caller edges, globals, initializer classification, unique signatures, or PIC resolution all fail closed.