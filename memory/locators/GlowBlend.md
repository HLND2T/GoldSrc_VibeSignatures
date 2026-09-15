---
title: GlowBlend locator
type: note
permalink: goldsrc-vibesignatures/locators/glowblend
tags:
  - locator
  - engine
  - func
---

# GlowBlend

## Symbol

- **Name**: `GlowBlend`
- **Category**: `func`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-GlowBlend.py`
- **Historical alias**: the symbol was emitted as `R_GlowBlend` until it was renamed to the real
  `engine/r_trans.c` name; older artifacts and configs use the `R_` form.

## Availability

- Declared in 10 engine configs: cof-5936, hl-10210, hl-3248, hl-3266, hl-3329, hl-3647, hl-4554, hl-6153, hl-8684, svencoop-10257. The symbol entry declares `platform: linux` in svencoop-10257.
- Platforms: **Linux-only** on hl-10210 and svencoop-10257 (those configs register the finder as `platform: linux`); Windows + Linux on hl-8684; Windows-only on the remaining configs, which ship no `hw.so`.
- Inlined / absent: **inlined on HL25 and SvEngine Windows**, where `GlowBlend` is folded into `R_DrawTEntitiesOnList`; those game versions are config-gated to Linux instead of emitting the inlined host. On GoldSrc/CoF (both platforms) and on HL25/SvEngine Linux it remains standalone.

## Predecessors

- `R_DrawTEntitiesOnList` (produced by `find-R_DrawTEntitiesOnList`, consumed via `expected_input`).

## How it is located

1. `xref_floats = ["19000.0", "0.005", "0.05"]` is the sole positive source, combined with `exclude_funcs = ["R_DrawTEntitiesOnList"]`.
2. The three constants are the falloff magic numbers owned by `GlowBlend` (`engine/r_trans.c`):
   `brightness = 19000 / (dist*dist);`
   `if (brightness < 0.05) ...`
   `pEntity->curstate.scale = dist * (1.0/200.0);` — folded to `0.005`.
3. Candidate = every function referencing all three constants; the function is unique on every build that keeps `GlowBlend` standalone.
4. `exclude_funcs` removes the inlined host: on the builds where `GlowBlend` was folded into `R_DrawTEntitiesOnList`, the host is the function carrying all three constants, and it must be rejected — the exclusion is resolved from the current `R_DrawTEntitiesOnList` artifact's exact function entry (not by name backtracking).
5. Emits the standard function fields; no byte signature participates.

## Pitfalls

- The exclusion is what makes the platform split work. Without it, the inlined host would match and the finder would emit `R_DrawTEntitiesOnList`'s address under the `GlowBlend` name.
- `exclude_funcs` uses the exact executable function start recovered from the predecessor artifact; do not substitute a name-based or adjacency-based exclusion.
- `19000.0` is a unique owner on every platform, so the anchor survives even where `0.05`/`0.005` are pooled differently.
- Do not "fix" the Windows gap by anchoring the inlined host: the config-level `platform: linux` gate is the sanctioned answer for hl-10210 and svencoop-10257.
