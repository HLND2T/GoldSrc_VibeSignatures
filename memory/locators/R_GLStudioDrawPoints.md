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
   - exactly two large branch targets -> identify the ATI path by its `GL_PN_TRIANGLES_ATI` (`0x87F0`) immediate and select the unique other branch; reject ambiguity rather than ranking by callee count;
   - no large branch and the body itself is `>= 800` bytes -> the body is the function.
6. Semantic gate: the chosen candidate must call the `StudioSetupSkin` slot's function. Because slot 29 may hold a forced-face wrapper that `jmp`s to the shared inner skin routine, any direct jump target of the slotted function is also accepted as a skin target.
7. Require exactly one surviving entry; emit the standard function fields (retrying with `allow_across_function_boundary` if the strict window fails).

## Pitfalls

- The table anchor must come from the segment image. `DataRefsTo` is unreliable on ELF and would miss the table entirely.
- Three distinct wrapper shapes must all be handled; a naive "slot 25 is the function" read yields the 9-line wrapper on CoF and a `jmp` thunk on HL25/SvEngine.
- Both the ordinary and ATI paths call `StudioSetupSkin`; that gate alone cannot distinguish them. For a two-branch wrapper, require a unique non-ATI path using the `GL_PN_TRIANGLES_ATI` capability marker. Callee-count ranking is not a valid identity check.
- The finder is not platform-gated, but only the three Linux-capable configs produce a `.linux.yaml`.

## HL 3266 ATI branch regression (2026-10-05)

- Trigger: MetaHookSv Renderer loaded CS3266 but crashed during map sign-on in the original studio vertex transform, writing through a null destination.
- Root cause: the two-branch wrapper at `0x1D91BE0` dispatches ordinary GL to `0x1D90660` and ATI PN triangles to `0x1D91290`. The ATI body has 12 direct callees versus 10 for ordinary GL; ranking by callee count published the ATI function and left the ordinary render path unhooked.
- Correct approach: identify the ATI OpenGL capability `GL_PN_TRIANGLES_ATI` (`0x87F0`), select the unique non-ATI branch, and retain the StudioSetupSkin semantic gate. Do not substitute hardcoded addresses or a reversed call-count heuristic.
- Verification: five regression tests exercise the actual WALK template (including ambiguity and missing-skin rejection). The real hl-3266 Windows finder generated `func_rva=0x90660`, `func_size=0x85A`. A local schema-8 candidate was exported and pruned through Renderer’s consumer manifest; CS3266 then loaded de_dust2, produced a screenshot, changed to de_dust and quit with exit code 0, with all ten installed plugins enabled.
- Scope: the finder correction is shared; the regenerated artifact and live game verification here cover hl-3266 Windows. Other published snapshots require their own regeneration before claiming corrected addresses. Local validation does not publish the remote catalog.

## Remaining ATI artifacts regenerated (PR #357, 2026-10-10)

- Trigger: shared-helper changes caused the full CI rebuild to compare every engine artifact; five Windows files still published the ATI body even though the finder had already been corrected in PR #333.
- Root cause: #333 regenerated hl-3266 only. The stale files for hl-3248/3329/3647/4554 and cof-5936 still had the ATI `push 0x87F0` signature.
- Correct approach: reuse the existing table/unique non-ATI branch finder and regenerate the remaining artifacts; do not change its anchor or weaken byte comparison.
- Fresh actual finder outputs: hl-3248 `0x1d90680`, hl-3329 `0x1d90540`, hl-3647 `0x1d906b0`, hl-4554 `0x1d9c600`, cof-5936 `0x1dc11e0`. Each run passed the existing StudioSetupSkin gate; each output signature has exactly one match in its raw executable sections.
- Scope: these five Windows artifacts. No new live-game validation or remote catalog publication is claimed.
