---
title: V_RenderView locator
type: note
permalink: goldsrc-vibesignatures/locators/v-renderview
tags:
  - locator
  - engine
  - func
---

# V_RenderView

## Symbol

- **Name**: `V_RenderView`
- **Category**: `func`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-VGui_ViewportPaintBackground-decompiles.py`

## Availability

- Declared in 10 engine configs: cof-5936, hl-10210, hl-3248, hl-3266, hl-3329, hl-3647, hl-4554, hl-6153, hl-8684, svencoop-10257.
- Platforms: Windows + Linux.
- Inlined / absent: none observed; it is a real, separate callee of the viewport callback. hl-10210 Windows body is 0x8B9 bytes.

## Predecessors

- `VGui_ViewportPaintBackground` (produced by `find-VGui_ViewportPaintBackground`, consumed via `expected_input` and `dependency_policy: required`).

## How it is located

1. Requires the current `VGui_ViewportPaintBackground.{platform}.yaml`; returns `False` without it.
2. `LLM_DECOMPILE` spec: symbol `V_RenderView`, prompt `prompt/call_llm_decompile.md`, expected section **`found_call`**, reference `references/{gamever}/engine/VGui_ViewportPaintBackground.{platform}.yaml`.
3. Semantic intent of the reference: `V_RenderView` is the direct call made between the viewport's refdef calculation and `GL_Set2D`. The LLM returns that `call`; shared validation resolves it against the current target and retries on mismatch.
4. Emitted fields: `func_name`, `func_va`, `func_rva`, `func_size`, `func_sig` (no `allow_across_function_boundary`).

## Pitfalls

- `found_call` supplies a *callee*; the artifact is a function, so validation must reject a call site address and the response must be the callee entry.
- The intended call sits in the middle of a long viewport callback (hl-10210: 0x199 bytes) — the reference annotation, not proximity, is what selects it.
- SvEngine has a distinct `R_RenderView`/`R_RenderView_SvEngine(int viewIdx)` entry; this finder is about the HL-family `V_RenderView` reached from `VGui_ViewportPaintBackground`, and the Sven sequence here is `VGui_ViewportPaintBackground`'s own call. Do not substitute the Sven `R_RenderView` artifact for it.
- No `allow_across_function_boundary` fallback is declared, so a non-unique signature here is a hard failure rather than a widened one.
