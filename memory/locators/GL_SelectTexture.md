---
title: GL_SelectTexture locator
type: note
permalink: goldsrc-vibesignatures/locators/gl-selecttexture
tags:
  - locator
  - engine
  - func
---

# GL_SelectTexture

## Symbol

- **Name**: `GL_SelectTexture`
- **Category**: `func`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-GL_BuildLightmaps-decompiles.py`

## Availability

- Declared in 10 engine configs: cof-5936, hl-10210, hl-3248, hl-3266, hl-3329, hl-3647, hl-4554, hl-6153, hl-8684, svencoop-10257.
- Platforms: Windows + Linux (no `platform:` gate in any config).
- Inlined / absent: none observed; the multitexture unit switch stays a real call in the lightmap pass on every validated branch.

## Predecessors

- `GL_BuildLightmaps.{platform}.yaml` (produced by `find-GL_BuildLightmaps`, consumed via `expected_input`).

## How it is located

- Same finder and same reference body as `GL_Bind`: an LLM_DECOMPILE spec with `symbol_name = GL_SelectTexture`, reference `references/{gamever}/engine/GL_BuildLightmaps.{platform}.yaml`, prompt `prompt/call_llm_decompile.md`, expected section `found_call`, required dependency on the `GL_BuildLightmaps.{platform}.yaml` artifact.
- Rationale (from the finder docstring): the lightmap rebuild body selects the multitexture units through `GL_SelectTexture` around the `GL_Bind` calls; the call sites are used to cross-validate the same function entry but are **not** emitted as callsite artifacts.
- Validation: unique `code_refs` target for the returned instruction, then entry inspection for the standard five function fields.

## Pitfalls

- Emitted from the same body as `GL_Bind`; a reference YAML that annotates only one of the two will fail the other spec.
- The finder intentionally emits only the function artifact, so downstream users must not expect a callsite/patch artifact for the unit-selection calls.
- Missing predecessor artifact or missing annotation fails closed (no fallback anchor).
