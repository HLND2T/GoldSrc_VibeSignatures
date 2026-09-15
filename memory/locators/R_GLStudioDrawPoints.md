---
title: R_GLStudioDrawPoints locator
type: note
permalink: goldsrc-vibesignatures/locators/r-glstudiodrawpoints
tags:
  - locator
  - engine
  - func
---

# R_GLStudioDrawPoints

## Symbol

- **Name**: `R_GLStudioDrawPoints`
- **Category**: `func`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-R_GLStudioDrawPoints.py`

## Availability

- Declared in 10 engine configs: cof-5936, hl-10210, hl-3248, hl-3266, hl-3329, hl-3647, hl-4554, hl-6153, hl-8684, svencoop-10257.
- Platforms: Windows + Linux where `hw.so` ships (hl-8684, hl-10210, svencoop-10257); the remaining seven configs are Windows binaries only.
- Inlined / absent: never inlined — the `studioapi_StudioDrawPoints` slot holds a code pointer to it or to a forwarder, so a table reference always keeps it reachable. Its *shape* varies: on CoF-era builds the slot holds the 9-line `IsATISmoothing` wrapper and the real GL body is its two-call branch; on GoldSrc/HL25/SvEngine, LTCG merges the wrapper and the GL body into one function which the slot references through a `jmp` thunk.

## Predecessors

- `studioapi_GetCurrentEntity` (slot 6) — also the primary scan value.
- `studioapi_StudioSetHeader` (slot 35).
- `studioapi_SetRenderModel` (slot 36).
- `studioapi_SetChromeOrigin` (slot 39).
  All four are produced by their own finders and consumed via `expected_input`.

## How it is located

1. Load all four studioapi artifacts; a missing one aborts.
2. Locate `engine_studio_api_t` by scanning data segments for the stored `studioapi_GetCurrentEntity` pointer value and back-computing `base = hit - 6*4`. A raw segment scan (not `DataRefsTo`) is used because ELF builds register the table through relocations and may record no code xref. Every candidate base is accepted only if slots 6/35/36/39 all hold the matching anchor values.
3. Read slot `25` (`StudioDrawPoints`) and slot `29` (`StudioSetupSkin`).
4. Chase forwarding layers, up to 4 hops, while the current function is `< 100` bytes and has exactly one `jmp`/`call` exit: this covers the `E9` jump thunk, and legacy MSVC 35->37-byte call chains.
5. Resolve the real body from the (possibly chased) function:
   - one large branch target (`> 100` bytes) and no further branching -> that target is `R_GLStudioDrawPoints` (pre-ATI builds ship the wrapper without the `ATINPatch` branch);
   - exactly two large branch targets -> the one with **more direct callees** wins (the `IsATISmoothing` wrapper form);
   - no large branch and the body itself is `>= 800` bytes -> the body is the function.
6. Semantic gate: the chosen candidate must call the `StudioSetupSkin` slot's function. Because slot 29 may hold a forced-face wrapper that `jmp`s to the shared inner skin routine, any direct jump target of the slotted function is also accepted as a skin target.
7. Require exactly one surviving entry; emit the standard function fields (retrying with `allow_across_function_boundary` if the strict window fails).

## Pitfalls

- The table anchor must come from the segment image. `DataRefsTo` is unreliable on ELF and would miss the table entirely.
- Three distinct wrapper shapes must all be handled; a naive "slot 25 is the function" read yields the 9-line wrapper on CoF and a `jmp` thunk on HL25/SvEngine.
- The `StudioSetupSkin` gate (with its jmp-target widening) is the only semantic check; the branch-count ranking alone could pick the wrong branch.
- The finder is not platform-gated, but only the three Linux-capable configs produce a `.linux.yaml`.
