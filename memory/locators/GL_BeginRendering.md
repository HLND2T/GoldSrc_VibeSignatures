---
title: GL_BeginRendering locator
type: note
permalink: goldsrc-vibesignatures/locators/gl-beginrendering
tags:
  - locator
  - engine
  - func
---

# GL_BeginRendering

## Symbol

- **Name**: `GL_BeginRendering`
- **Category**: `func`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-SCR_UpdateScreen_RenderBody-decompiles.py`

## Availability

- Declared in 10 engine configs: cof-5936, hl-10210, hl-3248, hl-3266, hl-3329, hl-3647, hl-4554, hl-6153, hl-8684, svencoop-10257.
- Platforms: Windows + Linux (no `platform:` gate in any config).
- Inlined / absent: none observed; it is the frame-opening call of every rendered frame.

## Predecessors

- `SCR_UpdateScreen_RenderBody.{platform}.yaml` (produced by `find-SCR_UpdateScreen_RenderBody`, consumed via `expected_input`).

## How it is located

- LLM_DECOMPILE spec, `symbol_name = GL_BeginRendering`, reference `references/{gamever}/engine/SCR_UpdateScreen_RenderBody.{platform}.yaml`, prompt `prompt/call_llm_decompile.md`, expected result section `found_call`, required dependency on the SCR_UpdateScreen_RenderBody artifact.
- Reference discriminator (from the finder docstring): `GL_BeginRendering` frames every rendered frame with four output pointers — zeroed x/y plus the window-rectangle width/height — which is what the annotated reference body pins.
- Validation: the returned instruction must exist in the current binary, its `code_refs` must resolve to exactly one function target, and the target entry is inspected through `_inspect_function_via_mcp` to emit `func_name`, `func_sig`, `func_va`, `func_rva`, `func_size`.
- The finder has no xref/signature discovery stage; the entry always comes from the LLM chain.

## Pitfalls

- The predecessor body is platform-dependent: on Windows it resolves to the full `SCR_UpdateScreen`, while Linux may resolve to a compiler-split body such as `SCR_UpdateScreen.part.*` — the reference YAML must be the one for the matching platform.
- Both the predecessor artifact and its annotated reference are required; either missing makes the skill return failure rather than fall back.
