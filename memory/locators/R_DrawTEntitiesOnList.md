---
title: R_DrawTEntitiesOnList locator
type: note
permalink: goldsrc-vibesignatures/locators/r-drawtentitiesonlist
tags:
  - locator
  - engine
  - func
---

# R_DrawTEntitiesOnList

## Symbol

- **Name**: `R_DrawTEntitiesOnList`
- **Category**: `func`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-R_DrawTEntitiesOnList.py`

## Availability

- Declared in 10 engine configs: cof-5936, hl-10210, hl-3248, hl-3266, hl-3329, hl-3647, hl-4554, hl-6153, hl-8684, svencoop-10257.
- Platforms: Windows + Linux.
- Inlined / absent: none observed.

## Predecessors

- None. `find-R_DrawTEntitiesOnList` has no `expected_input`; it is the root for the grouped `cl_parsecount` + `size_of_frame` finder.

## How it is located

1. `FUNC_XREFS` anchors on `FULLMATCH:Non-sprite set to glow!\n` — the diagnostic guarded by the glow render mode inside the transparent-entity loop.
2. The owning function of that string xref is `R_DrawTEntitiesOnList`.
3. Emitted fields: `func_name`, `func_sig`, `func_va`, `func_rva`, `func_size` (no `allow_across_function_boundary`).
4. Discovery never consumes an old artifact signature.

## Pitfalls

- The literal guards a specific branch (`currententity` render mode 3 with a non-sprite model), so it is a *body* anchor, not a table entry; it is unique per binary but do not treat the neighbouring `r_blend`/`GlowBlend` symbols as anchors.
- CoF's body differs from canonical HL: both sides of the `(cl_parsecount & CL_UPDATE_MASK)` frame-ring AND are memory-backed there (the counter has parser writes; the mask starts at 0x3f and supplies the AND). That is a real body difference, not an address the finder may copy — see `cl_parsecount`.
- R_DrawTEntitiesOnList is also an input to `find-R_GlowBlend` (Linux), so a wrong owner here propagates.
