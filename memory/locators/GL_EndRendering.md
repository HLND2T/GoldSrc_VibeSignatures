---
title: GL_EndRendering locator
type: note
permalink: goldsrc-vibesignatures/locators/gl-endrendering
tags:
  - locator
  - engine
  - func
---

# GL_EndRendering

## Symbol

- **Name**: `GL_EndRendering`
- **Category**: `func`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-SCR_UpdateScreen_RenderBody-decompiles.py`

## Availability

- Declared in 10 engine configs: cof-5936, hl-10210, hl-3248, hl-3266, hl-3329, hl-3647, hl-4554, hl-6153, hl-8684, svencoop-10257.
- Platforms: Windows + Linux (no `platform:` gate in any config).
- Inlined / absent: older builds keep only a **6-11 byte forwarding wrapper** that tails through the `VID_FlipScreen` pointer; the real body is not present at that entry on those builds.

## Predecessors

- `SCR_UpdateScreen_RenderBody.{platform}.yaml` (produced by `find-SCR_UpdateScreen_RenderBody`, consumed via `expected_input`).

## How it is located

- LLM_DECOMPILE spec, `symbol_name = GL_EndRendering`, reference `references/{gamever}/engine/SCR_UpdateScreen_RenderBody.{platform}.yaml`, prompt `prompt/call_llm_decompile.md`, expected section `found_call`, required dependency on the SCR_UpdateScreen_RenderBody artifact.
- This is the last stage of the per-frame pipeline mined from the screen body, so the annotated reference pins the frame-closing call.
- Because the legacy entry is a tiny `VID_FlipScreen` forwarding wrapper, the desired fields include `func_sig_allow_across_function_boundary:true`; the signature window is allowed to grow past the function's own extent to stay unique.
- Validation: unique `code_refs` target for the returned instruction, then entry inspection for `func_name`, `func_sig`, `func_va`, `func_rva`, `func_size`.

## Pitfalls

- Do **not** drop the across-boundary flag: within the 6-11 byte wrapper no unique in-function signature exists, and the standard prologue window cannot separate it from neighbours.
- The resolved entry is a thunk on legacy builds, so downstream callers get the wrapper address, not the flip-screen body. This finder does not set `func_sig_resolve_jmp_thunk`.
