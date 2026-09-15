---
title: Mod_LoadBrushModel locator
type: note
permalink: goldsrc-vibesignatures/locators/mod-loadbrushmodel
tags:
  - locator
  - engine
  - func
---

# Mod_LoadBrushModel

## Symbol

- **Name**: `Mod_LoadBrushModel`
- **Category**: `func`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-Mod_LoadBrushModel.py`, `ida_preprocessor_scripts/find-Mod_LoadModel-brushmodel-decompiles.py`

## Availability

- Declared in 10 engine configs: cof-5936, hl-10210, hl-3248, hl-3266, hl-3329, hl-3647, hl-4554, hl-6153, hl-8684, svencoop-10257.
- Platforms: Windows + Linux. Windows in every config; Linux only where a Linux engine module exists (hl-10210, hl-8684, svencoop-10257).
- Inlined / absent: none observed as a standalone function. On svencoop-10257 Linux there is no single-owner string anchor, so that one node falls back to the decompile producer.

## Predecessors

- `find-Mod_LoadBrushModel`: none.
- `find-Mod_LoadModel-brushmodel-decompiles`: `Mod_LoadModel.{platform}.yaml` (produced by `find-Mod_LoadModel`, `dependency_policy: required`).

## How it is located

Two producers, split by family/platform:

1. **Windows (all 10 configs) and classic Linux** — `find-Mod_LoadBrushModel` uses the exact string xref `FULLMATCH:Mod_LoadBrushModel: %s has wrong version number (%i should be %i)\n`. That literal comes from the BSP version check in the brush loader and belongs to `Mod_LoadBrushModel` only on the validated builds, so no other anchor is needed. Emits `func_name / func_sig / func_va / func_rva / func_size`.
2. **svencoop-10257 Linux** — `find-Mod_LoadModel-brushmodel-decompiles` runs LLM_DECOMPILE with the annotated reference `references/{gamever}/engine/Mod_LoadModel.{platform}.yaml` against the live `Mod_LoadModel` target body. The SvEngine dispatcher routes brush models to the BSP loader after reading the header; the LLM answers under `found_call` with the dispatch call, and its single code-ref target (`_inspect_function_via_mcp`) becomes `Mod_LoadBrushModel`. `expected_result_sections: ["found_call"]` makes an empty answer a failure.

The two nodes never overlap: the svencoop config gates `find-Mod_LoadBrushModel` to `platform: windows` precisely because the Linux literal has more than one owner there.

## Pitfalls

- The SvEngine Linux reason for the fallback is anchor ambiguity, not absence: the desert/version literals are shared, so the string path is rejected there rather than patched up with heuristics.
- `find-Mod_LoadModel-brushmodel-decompiles` depends on the *verified* `Mod_LoadModel` artifact, which on optimized Linux builds is a split body (`Mod_LoadModel.part.N`). If that artifact regresses to the public wrapper, the decompile reference no longer matches and the branch fails.
- The decompile chain only proves identity relationally (same callee as in the annotated reference), so a wrong-but-unique call site would be accepted silently — the annotated reference is the guard, and it must be regenerated whenever SvEngine's dispatcher changes.
- Blob engines (hl-3248..hl-3647) are Windows-only here and go through the string anchor against `hw.decrypt.dll`.
