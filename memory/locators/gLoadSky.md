---
title: gLoadSky locator
type: note
permalink: goldsrc-vibesignatures/locators/gloadsky
tags:
  - locator
  - engine
  - gv
---

# gLoadSky

## Symbol

- **Name**: `gLoadSky`
- **Category**: `gv`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producers**: `ida_preprocessor_scripts/find-R_LoadSkys-decompiles.py` (hl/CoF/HL25), `ida_preprocessor_scripts/find-R_LoadSkyBox_SvEngine-decompiles.py` (SvEngine)

## Availability

- Declared in 11 engine configs: cof-5936, hl-10210, hl-3248, hl-3266, hl-3329, hl-3647, hl-4554, hl-6153, hl-8684, svencoop-10257, svencoop-8948.
- Platforms: Windows + Linux.
- Inlined / absent: not applicable. The flag exists on every engine family, but the owning loader differs.
- Real-symbol-name evidence: the non-stripped Linux peers publish it — hl-10210/hw.so `0x806ce4`, hl-8684/hw.so `0x81c900`, svencoop-8948/hw.so `0x34d8034`. The name is therefore the engine's own, not a MetaHookSv invention.

## Predecessors

- hl/CoF/HL25: `R_LoadSkys.{platform}.yaml`.
- SvEngine: `R_LoadSkyBox_SvEngine.{platform}.yaml`.

## How it is located

`LLM_DECOMPILE` with `expected_result_sections: ["found_gv"]` against the annotated predecessor reference; the selected instruction's absolute operand is decoded by the shared x86 resolver.

- In `R_LoadSkys` the global is the entry gate (`cmp gLoadSky, 0` right after the security-cookie store) and the closing `mov gLoadSky, 0`.
- In `R_LoadSkyBox_SvEngine` it is the leading `cmp gLoadSky, 0` (return when clear) and the closing store.

## Pitfalls

- Two producers are required because `dependency_policy` is static per script while the `expected_input` differs per game family; a single script cannot satisfy `set(resolved_policy) == set(inferred_dependencies)` for both.
- SvEngine Linux is PIC (`mov ecx, ds:(gLoadSky - GOT)[ebx]`), so the emitted artifact carries `gv_pic_addend` (`0x2ee000` on svencoop-10257, `0x33a000` on svencoop-8948).
- On SvEngine the semantic twin of the HL25 `R_InitSky` setter is not in the loader; only the clear path is visible there, which is why the predecessor is the loader and not a setter.
