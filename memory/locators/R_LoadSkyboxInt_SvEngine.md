---
title: R_LoadSkyboxInt_SvEngine locator
type: note
permalink: goldsrc-vibesignatures/locators/r-loadskyboxint-svengine
tags:
  - locator
  - engine
  - func
---

# R_LoadSkyboxInt_SvEngine

## Symbol

- **Name**: `R_LoadSkyboxInt_SvEngine`
- **Category**: `func`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-R_LoadSkyboxInt_SvEngine.py`

## Availability

- Declared in 2 configs: svencoop-10257, svencoop-8948.
- Platforms: Windows + Linux.
- SvEngine-only. The classic hl/CoF/HL25 family prints the **two-space** banner `SKY:  ` from `R_LoadSkys`; the one-space literal `SKY: ` does not exist there, so this finder must never be registered for those configs.
- Real-symbol-name evidence: `svencoop-8948/hw.so` keeps `.symtab` and publishes `_Z15R_LoadSkyboxIntPKc` = `R_LoadSkyboxInt(char const*)`. The artifact name follows MetaHookSv's `_SvEngine`-suffixed convention already used by the sibling `R_LoadSkyBox_SvEngine`; `svencoop-10257/hw.so` is stripped and carries no name at all.

## Predecessors

- None.

## How it is located

`preprocess_common_skill` with a single exact string xref:

- `FULLMATCH:SKY: ` — **one trailing space, no newline**. Exactly one owning function on all four verified binaries: 10257 dll `0x1d5ffd0` / so `0x149650`, 8948 dll `0x1d5fc10` / so `0x195660`.

No byte signature participates in discovery. `_inspect_function_via_mcp` emits `func_name / func_sig / func_va / func_rva / func_size`.

## Pitfalls

- The single trailing space is load-bearing: the classic family literal has two trailing spaces, so the exact match is the only thing separating the SvEngine loader from `R_LoadSkys`.
- `FULLMATCH:` is required; a substring needle would also select the two-space family literal.
- Short-literal pollution of the shared IDB string list applies, and there is no structural fallback.
- This loader is called twice by [[R_LoadSkyBox_SvEngine]] (the requested skybox name and the `desert` fallback) and ends by clearing [[gLoadSky]].
