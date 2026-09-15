---
title: GL_Set2D locator
type: note
permalink: goldsrc-vibesignatures/locators/gl-set2d
tags:
  - locator
  - engine
  - func
---

# GL_Set2D

## Symbol

- **Name**: `GL_Set2D`
- **Category**: `func`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-SCR_UpdateScreen_RenderBody-decompiles.py`

## Availability

- Declared in 10 engine configs: cof-5936, hl-10210, hl-3248, hl-3266, hl-3329, hl-3647, hl-4554, hl-6153, hl-8684, svencoop-10257.
- Platforms: Windows + Linux (no `platform:` gate in any config).
- Inlined / absent: none observed; it is the HUD 2D projection setup reached through the same pipeline (MetaHook field `GLBeginHud`).

## Predecessors

- `SCR_UpdateScreen_RenderBody.{platform}.yaml` (produced by `find-SCR_UpdateScreen_RenderBody`, consumed via `expected_input`).

## How it is located

- LLM_DECOMPILE spec, `symbol_name = GL_Set2D`, reference `references/{gamever}/engine/SCR_UpdateScreen_RenderBody.{platform}.yaml`, prompt `prompt/call_llm_decompile.md`, expected section `found_call`, required dependency on the SCR_UpdateScreen_RenderBody artifact.
- Reference discriminator: two HUD call sites converge on the same entry.
- Desired fields include `func_sig_allow_across_function_boundary:true`, because the `GL_Set2D` bodies end in a tail jump and mirror the adjacent HUD pass helpers closely enough that only an across-boundary window stays unique.
- Validation: unique `code_refs` target for the returned instruction, then entry inspection for `func_name`, `func_sig`, `func_va`, `func_rva`, `func_size`.

## Pitfalls

- Dropping the across-boundary flag makes the signature collide with the neighbouring HUD helpers.
- The tail jump means the entry's own body does not contain the whole logic; callers should follow the tail chunk when reconstructing.
