---
title: R_ForceCVars locator
type: note
permalink: goldsrc-vibesignatures/locators/r-forcecvars
tags:
  - locator
  - engine
  - func
---

# R_ForceCVars

## Symbol

- **Name**: `R_ForceCVars`
- **Category**: `func`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-R_ForceCVars_R-AnimateLight.py`

## Availability

- Declared in 10 engine configs: cof-5936, hl-10210, hl-3248, hl-3266, hl-3329, hl-3647, hl-4554, hl-6153, hl-8684, svencoop-10257.
- Platforms: Windows + Linux where `hw.so` ships. In practice Linux artifacts are emitted only for hl-8684 and hl-10210; the other Linux-capable config, svencoop-10257, declares `expected_output_windows: R_ForceCVars.windows.yaml`, so its Linux artifact is never expected. The remaining seven configs are Windows binaries only.
- Inlined / absent: **absent on SvEngine Linux.** That layout opens the setup host straight with the `R_CheckVariables` call, so `R_ForceCVars` has no in-host call site and the walk reports `force_absent`. The symbol is written only when a site exists.

## Predecessors

- `R_CheckVariables` (produced by `find-R_CheckVariables`, consumed via `expected_input`, field `func_va`).

## How it is located

1. Load the `R_CheckVariables` artifact `func_va.`
2. Require exactly one caller host of `R_CheckVariables` (`R_SetupFrame`, or `R_RenderScene` with `R_SetupFrame` inlined).
3. Build the host's internal direct-call sequence in address order, skipping `<= 16`-byte thunks and indirect calls.
4. Require exactly one `R_CheckVariables` call site. `R_ForceCVars` is the internal call **immediately before** it, subject to two gates:
   - if the `R_CheckVariables` call site is the host's *first* internal call (`i == 0`), `R_ForceCVars` is reported absent;
   - if the previous call site is more than `MAX_NEIGHBOR_GAP = 96` bytes earlier, it is likewise reported absent.
5. Otherwise record the previous call's direct target as `R_ForceCVars` and emit it; the same host also yields `R_AnimateLight` from the following call.

## Pitfalls

- Absence is a legitimate outcome, not a failure: the SvEngine Linux layout genuinely has no in-host `R_ForceCVars` site, which is why svencoop-10257 splits the expectation with `expected_output_windows`.
- The 16-byte thunk filter and the 96-byte gap apply identically to both neighbours; a change to one silently changes the other's result.
- Both symbols share one host and one walk — if the `R_CheckVariables` host is not unique, both are lost.
