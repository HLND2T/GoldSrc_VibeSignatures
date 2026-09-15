---
title: S_ExtraUpdate locator
type: note
permalink: goldsrc-vibesignatures/locators/s-extraupdate
tags:
  - locator
  - engine
  - func
---

# S_ExtraUpdate

## Symbol

- **Name**: `S_ExtraUpdate`
- **Category**: `func`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-S_ExtraUpdate.py`

## Availability

- Declared in 10 engine configs: cof-5936, hl-10210, hl-3248, hl-3266, hl-3329, hl-3647, hl-4554, hl-6153, hl-8684, svencoop-10257.
- Platforms: Windows + Linux where `hw.so` ships (hl-8684, hl-10210, svencoop-10257); the remaining seven configs are Windows binaries only.
- Inlined / absent: never inlined; `engine/snd_dma.c` keeps it standalone in every registered build.

## Predecessors

- `R_RenderView` (produced by `find-R_RenderView`, consumed via `expected_input`, field `func_va`).
- `R_CheckVariables` (produced by `find-R_CheckVariables`, consumed via `expected_input`, field `func_va`).
- `R_RenderScene` is recovered *inside* this finder and is not a separate predecessor artifact.

## How it is located

1. Load both predecessor `func_va` values; either missing fails closed.
2. Recover `R_RenderScene` without a stored artifact. Primary path: the unique function that is both a callee of `R_RenderView` and a direct caller of `R_CheckVariables` (HL25/SvEngine inline `R_SetupFrame` into `R_RenderScene`). Fallback path: if that intersection is empty, take the unique function that calls a `R_CheckVariables` host and is itself a `R_RenderView` callee (GoldSrc/CoF keep `R_SetupFrame` standalone). A non-unique `R_RenderScene` candidate aborts.
3. `S_ExtraUpdate` is called by both `R_RenderView` and `R_RenderScene`, so compute `callees(R_RenderScene) ∩ callees(R_RenderView) - {R_RenderScene}`.
4. Apply the size gate `MAX_SIZE = 700` bytes. This is required, not cosmetic: `R_ForceCVars` (717 bytes) is legitimately called by both — from the inlined `R_Clear` in `R_RenderView` and from the setup-frame triple in `R_RenderScene` — and would otherwise leak into the intersection.
5. Require exactly one surviving candidate; emit it (retrying with `allow_across_function_boundary` if needed).

## Pitfalls

- `MAX_SIZE = 700` is tuned to fall just below `R_ForceCVars`'s 717 bytes. Raising it reintroduces the ambiguity and the symbol is lost.
- The callee sets are filtered to exact internal function starts with size `> 16` bytes, so import/CRT thunks never enter the intersection.
- The two `R_RenderScene` recovery paths correspond to real codegen differences (inlined vs. standalone `R_SetupFrame`); both must stay available or one engine family silently loses the symbol.
- `R_CheckVariables` is a shared predecessor with `find-R_ForceCVars_R-AnimateLight`; it must be resolved before either finder can run.
