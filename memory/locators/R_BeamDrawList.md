---
title: R_BeamDrawList locator
type: note
permalink: goldsrc-vibesignatures/locators/r-beamdrawlist
tags:
  - locator
  - engine
  - func
---

# R_BeamDrawList

## Symbol

- **Name**: `R_BeamDrawList`
- **Category**: `func`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-R_DrawParticles-calls.py`

## Availability

- Declared in 10 engine configs: cof-5936, hl-10210, hl-3248, hl-3266, hl-3329, hl-3647, hl-4554, hl-6153, hl-8684, svencoop-10257.
- Platforms: Windows on every registered config; Linux only where `hw.so` ships *and* the producing finder is not Windows-gated (hl-8684, svencoop-10257). On hl-10210 the whole finder is `platform: windows`, so only `R_BeamDrawList.windows.yaml` exists there.
- Inlined / absent: never inlined — it stays a distinct mid-size pass that the particle renderer calls.

## Predecessors

- `R_DrawParticles` (produced by `find-R_DrawParticles`, consumed via `expected_input`, field `func_va`).

## How it is located

1. Load the `R_DrawParticles` artifact `func_va`; the walk covers **only** that function's body.
2. Enumerate the renderer's internal direct calls (exact function starts, size `> THUNK_MAX = 16`); fewer than 3 internal calls aborts.
3. `R_BeamDrawList` is the candidate with `BEAM_MIN = 250 <= size <= BEAM_MAX = 900` bytes whose caller set is exactly `{R_DrawParticles}` and which itself calls at least one function of `>= 250` bytes (the beam-draw pair `R_BeamDraw` / `R_DrawBeamEntList`).
4. Require exactly one beam candidate and at most one tracer candidate; more than one of either aborts.
5. Emit the standard function fields (retrying with `allow_across_function_boundary` when needed). No byte signature participates.

## Pitfalls

- The renderer is the beam pass's *only* caller, and that exclusivity is enforced (`callers(c) == {R_DrawParticles}`). A future extra caller breaks the gate rather than silently picking a different function.
- The size window and the "has a large callee" test both matter; the size window alone would admit other mid-size helpers in the renderer.
- The beam candidate is explicitly removed from the tracer pool before the tracer test, so the two symbols cannot collapse onto one address.
- On hl-10210 the finder is Windows-only because GCC's chunk attribution for this renderer is unreliable; `R_BeamDrawList.linux.yaml` is therefore not produced even though `hw.so` exists.
