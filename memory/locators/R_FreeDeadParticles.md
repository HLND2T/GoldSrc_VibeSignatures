---
title: R_FreeDeadParticles locator
type: note
permalink: goldsrc-vibesignatures/locators/r-freedeadparticles
tags:
  - locator
  - engine
  - func
---

# R_FreeDeadParticles

## Symbol

- **Name**: `R_FreeDeadParticles`
- **Category**: `func`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-R_DrawParticles-calls.py`

## Availability

- Declared in 10 engine configs: cof-5936, hl-10210, hl-3248, hl-3266, hl-3329, hl-3647, hl-4554, hl-6153, hl-8684, svencoop-10257.
- Platforms: Windows on every registered config; Linux only where `hw.so` ships *and* the producing finder is not Windows-gated — that is hl-8684 and svencoop-10257. On hl-10210 the finder is `platform: windows`, so only the Windows artifact exists.
- Inlined / absent: never inlined; the small free helper stays a standalone function on both platforms where it is produced.

## Predecessors

- `R_DrawParticles` (produced by `find-R_DrawParticles`, consumed via `expected_input`, field `func_va`).

## How it is located

1. Load the `R_DrawParticles` artifact `func_va`; the walk covers only the renderer body and its direct callees.
2. Seed the candidate pool from two sources:
   - `callees(R_DrawParticles) ∩ callees(R_TracerDraw)` when a tracer pass exists (`R_TracerDraw` is not inlined); the tracer pass frees its own dead list through the same helper;
   - any internal callee of the renderer that appears `>= 2` times in the renderer body (`seq` call counts) — the inlined-tracer case and the repeated frees.
   The pool then drops `R_DrawParticles`, the beam candidate and the tracer candidate.
3. Filter the pool: `MIN_BODY = 60 <= size <= FREE_MAX = 400` bytes, `<= 1` callee of its own, `2..10` distinct callers, and (when a tracer exists) `R_DrawParticles` must be one of its callers.
4. When `R_TracerDraw` is inlined, the count threshold rises to `>= 3` occurrences in the renderer body, because the renderer then frees both its own and the tracer's list; this drops the shared two-call helpers such as the cull test.
5. Require exactly one candidate; emit the standard function fields (retrying with `allow_across_function_boundary` when needed).

## Pitfalls

- The `>= 3`-occurrence rule is a direct consequence of tracer inlining; lowering it re-admits unrelated small helpers and the candidate stops being unique.
- The uniqueness requirement is on the filtered pool, not on the seed set — a near-miss such as the cull test is excluded by the "at most one callee" and caller-count gates.
- `R_FreeDeadParticles` shares its predecessor and its body walk with `R_BeamDrawList` and `R_TracerDraw`; a failure in any of the three aborts the whole finder for that platform.
