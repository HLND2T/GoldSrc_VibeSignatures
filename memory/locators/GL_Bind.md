---
title: GL_Bind locator
type: note
permalink: goldsrc-vibesignatures/locators/gl-bind
tags:
  - locator
  - engine
  - func
---

# GL_Bind

## Symbol

- **Name**: `GL_Bind`
- **Category**: `func`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-GL_BuildLightmaps-decompiles.py`

## Availability

- Declared in 10 engine configs: cof-5936, hl-10210, hl-3248, hl-3266, hl-3329, hl-3647, hl-4554, hl-6153, hl-8684, svencoop-10257.
- Platforms: Windows + Linux (no `platform:` gate in any config).
- Inlined / absent: the entry exists on both platforms (metadata kind is `both` in every config). The Linux/SvEngine builds inline the `GL_Bind` call out of `GL_LoadFilterTexture`'s body — which is why that finder carries `GL_Bind.{platform}.yaml` only as an optional input — but the lightmap pass here still reaches a real `GL_Bind` entry.

## Predecessors

- `GL_BuildLightmaps.{platform}.yaml` (produced by `find-GL_BuildLightmaps`, consumed via `expected_input`).

## How it is located

- One LLM_DECOMPILE spec, `symbol_name = GL_Bind`, reference `references/{gamever}/engine/GL_BuildLightmaps.{platform}.yaml`, prompt `prompt/call_llm_decompile.md`, expected result section `found_call`, with a **required** dependency on the `GL_BuildLightmaps.{platform}.yaml` artifact.
- Rationale (from the finder docstring): `GL_BuildLightmaps` rebinds lightmap textures through `GL_Bind` (engine/gl_rsurf.c), so the lightmap pass carries the densest, most distinct `GL_Bind` call; that call site resolves uniquely from the annotated reference body on every validated branch.
- Validation: the returned `insn_va`/`insn_disasm` pair must be a real instruction in the exported current-binary target, and the resolved call must have exactly one `code_ref` target. The entry is then inspected through `_inspect_function_via_mcp` to build `func_name`, `func_sig`, `func_va`, `func_rva`, `func_size`.
- No xref/byte-signature stage exists in this finder: the entry always comes from the LLM `found_call` chain.

## Pitfalls

- The call site is deliberately **not** emitted as a patch/callsite artifact: it is only the anchor for the function entry.
- The same body also yields `GL_SelectTexture`; its call sites cross-validate the same entries, so a mismatch between the two means the reference body was mis-annotated.
- Fails closed when either the GL_BuildLightmaps artifact or the annotated reference YAML is missing.
