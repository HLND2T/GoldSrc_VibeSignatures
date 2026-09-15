---
title: R_DrawParticles locator
type: note
permalink: goldsrc-vibesignatures/locators/r-drawparticles
tags:
  - locator
  - engine
  - func
---

# R_DrawParticles

## Symbol

- **Name**: `R_DrawParticles`
- **Category**: `func`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-R_DrawParticles.py`

## Availability

- Declared in 10 engine configs: cof-5936, hl-10210, hl-3248, hl-3266, hl-3329, hl-3647, hl-4554, hl-6153, hl-8684, svencoop-10257.
- Platforms: Windows + Linux where `hw.so` ships (hl-8684, hl-10210, svencoop-10257); the remaining seven configs are Windows binaries only. The finder is not platform-gated.
- Inlined / absent: never inlined; `engine/r_part.c R_DrawParticles` keeps its own body — including on GCC Linux builds, where it survives as the host of the inlined particle passes (see `R_TracerDraw`).

## Predecessors

- None. It is the anchor for the `find-R_DrawParticles-calls` successor.

## How it is located

1. `xref_floats = ["20.0", "0.004"]` is the sole positive source; the candidate set is every function whose body references both constants.
2. The constants come from the GLQUAKE sprite-scale hack inside the function:
   `if (scale < 20) scale = 1; else scale = 1 + scale * 0.004;`
   `20` is compared as a **float** constant; the C literal `0.004` is a **double** and is therefore stored as an 8-byte constant.
3. The shared matcher reads each candidate constant at the decoded operand's actual width, so the MSVC f64 / GCC f32 mixture is handled without a per-compiler special case.
4. The function referencing both constants is unique on every validated engine build (GoldSrc, HL25, SvEngine and CoF, both platforms). Emits the standard function fields; no byte signature participates.

## Pitfalls

- `xref_floats` spec values must be strings; `_normalize_func_xref_specs` silently rejects non-`str` entries.
- The `0.004` anchor only exists as an 8-byte value. A finder that scans for f32 instances misses it, and an f64 pool entry whose low word reinterprets as a wanted f32 must not be credited by a double reader.
- The `20.0` comparison is a float, not an integer — an integer-immediate scan finds nothing.
- `R_DrawParticles` is a DAG root for three more symbols; if it fails, `R_FreeDeadParticles`, `R_TracerDraw` and `R_BeamDrawList` all fail with it.
