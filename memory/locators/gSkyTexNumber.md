---
title: gSkyTexNumber locator
type: note
permalink: goldsrc-vibesignatures/locators/gskystexnumber
tags:
  - locator
  - engine
  - gv
---

# gSkyTexNumber

## Symbol

- **Name**: `gSkyTexNumber`
- **Category**: `gv`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producers**: `ida_preprocessor_scripts/find-R_LoadSkys-decompiles.py` (hl/CoF/HL25), `ida_preprocessor_scripts/find-R_LoadSkyBox_SvEngine-decompiles.py` (SvEngine)

## Availability

- Declared in 11 engine configs: cof-5936, hl-10210, hl-3248, hl-3266, hl-3329, hl-3647, hl-4554, hl-6153, hl-8684, svencoop-10257, svencoop-8948.
- Platforms: Windows + Linux.
- Inlined / absent: not applicable. It is a six-element `int` array on every family; only the owning loader differs.
- Real-symbol-name evidence: hl-10210/hw.so `0x806ccc`, hl-8684/hw.so `0x81c8e0`, svencoop-8948/hw.so `0x34d8040`.

## Predecessors

- hl/CoF/HL25: `R_LoadSkys.{platform}.yaml`.
- SvEngine: `R_LoadSkyBox_SvEngine.{platform}.yaml`.

## How it is located

`LLM_DECOMPILE` with `expected_result_sections: ["found_gv"]` against the annotated predecessor reference.

- In `R_LoadSkys` it is the array base used by the `if (gSkyTexNumber[i])` clear loop and the two per-face fill paths (`mov esi, offset gSkyTexNumber` / `gSkyTexNumber[esi*4]`).
- In `R_LoadSkyBox_SvEngine` it is the base of the delete loop (`mov esi, offset gSkyTexNumber`, bounded by `cmp esi, offset gLoadSky`) and the six `desert`-fallback stores.

## Pitfalls

- **Do not derive it as `gLoadSky + 4`.** The two slots are adjacent only on the optimized builds (hl-10210 both platforms, hl-8684 Windows, SvEngine). On cof-5936 they are far apart (`gLoadSky 0x23c9418`, `gSkyTexNumber 0x27fc300`), and on the BLOB builds too (`0x23cd2c4` vs `0x280e0a0` on hl-3248). Each binary must be read on its own.
- CoF and BLOB keep the newer fixed-texture-id scheme (`gSkyTexNumber[i] = ((paletteIndex + 1) << 16) | (0x16A8 + i)`), so the store shape differs from the classic `GL_GenTexture` result even though the slot is the same.
- SvEngine Linux is PIC; the artifact carries `gv_pic_addend` (`0x2ee000` / `0x33a000`).
- The array length is fixed at six and is witnessed by the loop bound (`gSkyTexNumber+18h == gLoadSky`) rather than by a length symbol.
