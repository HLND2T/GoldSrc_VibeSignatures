---
title: R_TracerDraw locator
type: note
permalink: goldsrc-vibesignatures/locators/r-tracerdraw
tags:
  - locator
  - engine
  - func
---

# R_TracerDraw

## Symbol

- **Name**: `R_TracerDraw`
- **Category**: `func`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-R_DrawParticles-calls.py`

## Availability

- Declared in 10 engine configs: cof-5936, hl-10210, hl-3248, hl-3266, hl-3329, hl-3647, hl-4554, hl-6153, hl-8684, svencoop-10257.
- Platforms: **Windows-only in every registered config.** The symbol entry declares `platform: windows` in svencoop-10257; on hl-10210 the whole finder is `platform: windows`; everywhere else the split is expressed as `expected_output_windows: R_TracerDraw.windows.yaml`. Only `R_TracerDraw.windows.yaml` artifacts exist for all ten configs.
- Inlined / absent: **absent on GCC builds.** GoldSrc Linux and the other GCC targets inline `R_TracerDraw` into the `R_DrawParticles` body; the walk then reports `tracer_inlined` and no artifact is written for that platform.

## Predecessors

- `R_DrawParticles` (produced by `find-R_DrawParticles`, consumed via `expected_input`, field `func_va`).

## How it is located

1. Load the `R_DrawParticles` artifact `func_va`; the walk covers only that function's body.
2. Enumerate the renderer's internal direct calls (exact function starts, size `> 16`).
3. `R_TracerDraw` is the candidate with `size >= TRACER_MIN = 900` bytes whose caller set is exactly `{R_DrawParticles}` and which is not the already-selected `R_BeamDrawList`.
4. Exactly one tracer candidate at most; more than one aborts.
5. If no tracer candidate exists, `R_TracerDraw` is recorded as absent (`tracer_inlined`) — that is the expected GCC outcome, and the requesting platform must not expect the artifact.
6. Otherwise emit the standard function fields (retrying with `allow_across_function_boundary` when needed).

## Pitfalls

- Absence is meaningful, not a failure: the caller's `expected_output_windows` split is the contract that keeps the missing Linux artifact from being treated as a finder error.
- The `>= 900`-byte test plus sole-caller exclusivity is the whole discriminator; without the size floor the beam pass or another large renderer helper could be selected.
- With the tracer inlined, the free-list candidate gate tightens (`counts >= 3`) because the renderer then frees both its own and the tracer's list — see `R_FreeDeadParticles`.
- Discovery never uses a byte signature; the emitted signature is only ever a runtime validation artifact.
