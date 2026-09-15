---
title: R_AnimateLight locator
type: note
permalink: goldsrc-vibesignatures/locators/r-animatelight
tags:
  - locator
  - engine
  - func
---

# R_AnimateLight

## Symbol

- **Name**: `R_AnimateLight`
- **Category**: `func`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-R_ForceCVars_R-AnimateLight.py`

## Availability

- Declared in 10 engine configs: cof-5936, hl-10210, hl-3248, hl-3266, hl-3329, hl-3647, hl-4554, hl-6153, hl-8684, svencoop-10257.
- Platforms: Windows + Linux where `hw.so` ships (hl-8684, hl-10210, svencoop-10257); the remaining seven configs are Windows binaries only.
- Inlined / absent: never inlined; it is emitted on every registered target. `R_SetupFrame`, which contains the triple, *is* inlined into `R_RenderScene` on HL25 and SvEngine, but that only moves the call sites, it does not remove this symbol.

## Predecessors

- `R_CheckVariables` (produced by `find-R_CheckVariables`, consumed via `expected_input`, field `func_va`).

## How it is located

1. Load the `R_CheckVariables` artifact `func_va`; missing artifact or missing `func_va` fails closed.
2. Find every caller of `R_CheckVariables` (`CodeRefsTo` -> owning function). Require **exactly one** host — `R_SetupFrame` (standalone on GoldSrc/CoF) or `R_RenderScene` with the inlined `R_SetupFrame` (HL25/SvEngine).
3. Enumerate the host's *internal* direct calls in address order: `call` with a direct target that is an exact function start and whose size is `> 16` bytes (import/CRT thunks excluded).
4. There must be exactly one `R_CheckVariables` call site. The **next** internal call in the sequence is `R_AnimateLight`; if its distance from the `R_CheckVariables` call site exceeds `MAX_NEIGHBOR_GAP = 96` bytes, the walk fails (no in-host animate neighbour).
5. Emit the located entry, retrying with `allow_across_function_boundary` if the strict window produces no signature.

## Pitfalls

- The whole locator is order- and adjacency-based inside one host; it does not use a byte signature.
- The 16-byte thunk filter and the 96-byte gap are load-bearing constants, not tunables.
- If the `R_CheckVariables` host is ever not unique (a second caller appears, for instance through an inlined copy), `R_AnimateLight` and `R_ForceCVars` are both lost — the finder returns `False` and neither symbol is written.
