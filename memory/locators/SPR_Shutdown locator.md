---
title: SPR_Shutdown locator
type: note
permalink: goldsrc-vibesignatures/locators/spr-shutdown-locator
tags:
- locator
- engine
- func
---

# SPR_Shutdown

## Symbol

- **Name**: `SPR_Shutdown`
- **Category**: `func`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-Mod_UnloadSpriteTextures.py`

## Availability

- Declared in all 11 engine configs: cof-5936, hl-3248, hl-3266, hl-3329, hl-3647, hl-4554, hl-6153, hl-8684, hl-10210, svencoop-8948, svencoop-10257.
- Windows on all 11 configs; Linux on hl-8684, hl-10210, svencoop-8948, and svencoop-10257.
- Not applicable to cstrike/czero/czeror because those configs have no engine module.
- The function remains independent in every validated target; HL25/SvEngine inline the broader `ClientDLL_Shutdown` flow, not `SPR_Shutdown`.

## Predecessors

- No artifact predecessor. The producer starts from current-IDB string anchors and emits this function together with `[[Mod_UnloadSpriteTextures locator]]`, `[[gSpriteList locator]]`, and `[[gSpriteCount locator]]`.

## How it is located

1. Locate the sprite-texture unload candidate from `%s_%i` owners/callers and the stable model/sprite member offsets.
2. Normalize ELF PLT/internal thunks and collect the candidate's semantic callers.
3. Require one caller that invokes the target once, invokes one free helper twice, and implements a 12-byte `SPRITELIST` loop.
4. Intersect globals stored by that caller with globals used by the uniquely anchored `SPR_Load`; the intersection and initializer cross-check must identify exactly the sprite list/count pair.
5. Generate and uniquely validate `func_sig` only after discovery.

## Pitfalls

- `SPR_Shutdown_NoModelFree` accesses and clears the same globals but does not call `Mod_UnloadSpriteTextures`; the required caller edge excludes it.
- Windows import thunks without internal bodies remain thunk identities for call counting. ELF PLT thunks resolve to their internal bodies.
- Any missing/ambiguous caller, repeated free helper, stride, global pair, initializer, or signature fails closed.