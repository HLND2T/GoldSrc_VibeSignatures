---
title: V_BuildGammaTable locator
type: note
permalink: goldsrc-vibesignatures/locators/v-build-gamma-table-locator
tags:
- locator
- engine
- func
- svengine
---

# V_BuildGammaTable

## Symbol

- **Name**: `V_BuildGammaTable`
- **Category**: `func`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-V_BuildGammaTable.py`

## Availability

SvEngine only: svencoop-8948 and svencoop-10257, Windows + Linux. Linux 8948 exports `_Z17V_BuildGammaTablef`. Linux 10257 is stripped; the same float set still uniquely owns `sub_134640` (size `0x407`). Windows VA equals the existing `BuildGammaTable` artifact.

## Predecessors

None. Same float set as `find-BuildGammaTable`: `xref_floats = ["1023.0", "0.075", "0.875"]`.

## How it is located

The brightness-shift coefficients uniquely identify the builder, including PIC GOT-relative pools on SvEngine Linux (shared `_float_fallback_owners`).

## Pitfalls

- Do not register this skill on GoldSrc/HL25/CoF; those keep `BuildGammaTable`.
- `find-BuildGammaTable-globals` on svencoop consumes this artifact, not `BuildGammaTable`.
