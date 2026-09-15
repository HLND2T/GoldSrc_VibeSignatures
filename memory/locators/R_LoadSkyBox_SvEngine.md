---
title: R_LoadSkyBox_SvEngine locator
type: note
permalink: goldsrc-vibesignatures/locators/r-loadskybox-svengine
tags:
  - locator
  - engine
  - func
---

# R_LoadSkyBox_SvEngine

## Symbol

- **Name**: `R_LoadSkyBox_SvEngine`
- **Category**: `func`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-R_LoadSkyBox_SvEngine.py`, `ida_preprocessor_scripts/find-SkyboxCommand-decompiles.py`

## Availability

- Declared in 1 config: svencoop-10257 (no `platform` restriction on the symbol).
- Platforms: Windows + Linux — but per-platform producers: Windows via the string anchor, Linux via the decompile branch.
- Inlined / absent: on SvEngine Linux the desert literal is shared by the parameterised wrapper and an inlined no-argument function, so the string anchor is not used there. This is a SvEngine-only symbol: the classic hl/CoF/HL25 skybox path is `R_LoadSkys`, not this loader.
- Not applicable to cstrike/czero/czeror (no engine module in this repo).

## Predecessors

- `find-R_LoadSkyBox_SvEngine`: none.
- `find-SkyboxCommand-decompiles`: `SkyboxCommand.{platform}.yaml` (produced by `find-SkyboxCommand-svencoop`, `dependency_policy: required`).

## How it is located

Two producers, split by platform:

1. **Windows (svencoop-10257)** — `find-R_LoadSkyBox_SvEngine` uses the exact string xref `FULLMATCH:desert`. The outer loader gates on the loading state, clears the six sky textures, calls the internal loader and falls back to the `desert` skybox before filling a missing texture; on SvEngine Windows that literal has exactly one function owner.
2. **Linux (svencoop-10257)** — `find-SkyboxCommand-decompiles` runs LLM_DECOMPILE with the annotated reference `references/svencoop-10257/engine/SkyboxCommand.{platform}.yaml` against the live `SkyboxCommand` target body. `SkyboxCommand` forwards `Cmd_Argv(1)` to the outer loader, so the LLM's `found_call` entry pins the loader call site; the instruction's single code-ref target becomes `R_LoadSkyBox_SvEngine` via `_inspect_function_via_mcp`. `expected_result_sections: ["found_call"]` makes an empty answer a failure.

Both paths emit `func_name / func_sig / func_va / func_rva / func_size`.

## Pitfalls

- The Linux fallback exists because the desert literal has **two** function owners there (parameterised wrapper + inlined no-argument function). Do not "fix" it by relaxing the single-owner rule — that would pick the inlined clone.
- The SvEngine body genuinely differs from the shared hl family, so it keeps its own `svencoop-10257` reference YAML; the reference must be regenerated when SvEngine changes the loader.
- `find-SkyboxCommand-decompiles` depends on the verified `SkyboxCommand` artifact (Linux-only). If that predecessor is missing, the branch fails rather than falling back to the string anchor.
- MetaHookSv's `gl_hooks.cpp` keeps the same role for this loader, so it is a usable cross-check but not part of the anchor chain.
