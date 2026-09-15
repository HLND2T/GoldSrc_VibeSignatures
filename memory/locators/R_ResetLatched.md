---
title: R_ResetLatched locator
type: note
permalink: goldsrc-vibesignatures/locators/r-resetlatched
tags:
  - locator
  - engine
  - func
---

# R_ResetLatched

## Symbol

- **Name**: `R_ResetLatched`
- **Category**: `func`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-R_ResetLatched.py`

## Availability

- Declared in 10 engine configs: cof-5936, hl-10210, hl-3248, hl-3266, hl-3329, hl-3647, hl-4554, hl-6153, hl-8684, svencoop-10257.
- Platforms: Windows + Linux where `hw.so` ships (hl-8684, hl-10210, svencoop-10257); the remaining seven configs are Windows binaries only.
- Inlined / absent: never inlined; `engine/cl_ents.c` keeps it standalone. Its *call-site count* is platform-dependent — see the callsite symbols.

## Predecessors

- None. `CL_LinkPacketEntities` is recovered inside this same finder from the diagnostic literal and is not a separate artifact.

## How it is located

1. Find the unique NUL-terminated C string `"Tried to link edict %i without model\n"` in non-executable segments, then collect the owners of every data reference to it. Require exactly one owner — `CL_LinkPacketEntities`.
2. Enumerate `CL_LinkPacketEntities`'s internal direct calls (exact function starts, size `> 16`).
3. Keep candidates that are called `>= 2` times from that body (the full reset and the `EF_NOINTERP` reset), with `MIN_SIZE = 100 <= size <= MAX_SIZE = 1200`, having `CL_LinkPacketEntities` among their callers plus `MIN_EXTRA_CALLERS = 1 .. MAX_EXTRA_CALLERS = 4` further callers (the other `cl_ents` link helpers such as `CL_ResetLatchedState` / `CL_LinkPlayers`).
4. `R_ResetLatched`'s callers are exactly the `cl_ents` link helpers, so the surviving candidate with the **fewest total callers** wins; a tie fails closed.
5. Emit the function artifact (retrying with `allow_across_function_boundary` when needed); the call sites are emitted by the shared callsite helper.

## Pitfalls

- The "fewest callers wins, ties fail" tie-break is the semantic selection, not a heuristic; other doubly-called helpers in the body are pushed out by it.
- The diagnostic literal must be unique. If a second owner appears the finder aborts rather than guessing.
- The size window `100..1200` bytes and the `1..4` extra-caller window are load-bearing.
- `R_ResetLatched` is the callee of the numbered callsite patches; the callsite count is derived from the expected outputs and must be contiguous from 0.
