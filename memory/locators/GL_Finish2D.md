---
title: GL_Finish2D locator
type: note
permalink: goldsrc-vibesignatures/locators/gl-finish2d
tags:
  - locator
  - engine
  - func
---

# GL_Finish2D

## Symbol

- **Name**: `GL_Finish2D`
- **Category**: `func`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-SCR_UpdateScreen_RenderBody-decompiles.py`

## Availability

- Declared in 10 engine configs: cof-5936, hl-10210, hl-3248, hl-3266, hl-3329, hl-3647, hl-4554, hl-6153, hl-8684, svencoop-10257.
- Platforms: Windows + Linux (no `platform:` gate in any config).
- Inlined / absent: none observed; the HUD pass closes with a real call.

## Predecessors

- `SCR_UpdateScreen_RenderBody.{platform}.yaml` (produced by `find-SCR_UpdateScreen_RenderBody`, consumed via `expected_input`).

## How it is located

- LLM_DECOMPILE spec, `symbol_name = GL_Finish2D`, reference `references/{gamever}/engine/SCR_UpdateScreen_RenderBody.{platform}.yaml`, prompt `prompt/call_llm_decompile.md`, expected section `found_call`, required dependency on the SCR_UpdateScreen_RenderBody artifact.
- Reference discriminator (from the finder docstring): the HUD pass has **two** `GL_Finish2D` call sites that converge on the same entry, which is what the annotation pins.
- Validation: the returned instruction must have exactly one `code_refs` target; the entry is then inspected for the standard five function fields.
- No xref/byte-signature discovery stage — the entry comes only from the LLM chain.

## Pitfalls

- The two HUD call sites must resolve to the same entry; if the reference annotation only marks one, the spec still succeeds, but a mis-annotated third call site (e.g. a different 2D-finish helper) would resolve to the wrong function.
- Requires both the predecessor artifact and its platform-matching reference YAML.
