---
title: GameStudioRenderer_StudioRenderModel locator
type: note
permalink: goldsrc-vibesignatures/locators/gamestudiorenderer-studiorendermodel
tags:
  - locator
  - client
  - vfunc
---

# GameStudioRenderer_StudioRenderModel

## Symbol

- **Name**: `GameStudioRenderer_StudioRenderModel`
- **Category**: `vfunc`
- **Module**: client (`client.dll` / `client.so`)
- **Producer**: `ida_preprocessor_scripts/find-GameStudioRenderer_StudioDrawModel-decompiles.py`

## Availability

- Declared in 14 client configs: cstrike-3248/3647/4554/6153/8684/10210, czero-8684/10210,
  czeror-8684/10210, hl-8684/10210, cof-5936, svencoop-10257.
- Platforms: Windows + Linux only where the client module ships a Linux half — cstrike-10210,
  cstrike-6153, cstrike-8684, hl-10210, hl-8684, svencoop-10257. The other 8 configs
  (cof-5936, cstrike-3248/3647/4554, czero-8684/10210, czeror-8684/10210) declare only
  `module_windows: client.dll`, so those runs are Windows-only.
- Always present. Always emits `vfunc_sig_allow_across_function_boundary: true`.

## Predecessors

- `GameStudioRenderer_StudioDrawModel.<platform>.yaml` (required reference for the LLM step).
- `GameStudioRenderer_vtable.<platform>.yaml` — supplies `vfunc_index` / `vfunc_offset`.

## How it is located

1. Produced by the **DrawModel** decompile finder — not by
   `find-GameStudioRenderer_StudioRenderModel-decompiles`, which consumes this artifact as its
   own required input.
2. `preprocess_common_skill` with this name in `func_names` and
   `func_vtable_relations = ("GameStudioRenderer_StudioRenderModel", "GameStudioRenderer")`; no
   `xref_strings` anchor is declared and `old_yaml_map=None` disables the signature fast path,
   so the `LLM_DECOMPILE` spec always runs.
3. Spec: prompt `prompt/call_llm_decompile.md` against the required reference
   `references/{gamever}/client/GameStudioRenderer_StudioDrawModel.<platform>.yaml`,
   `expected_result_sections = ["found_vcall", "found_funcptr"]`. The canonical hl-10210 Windows
   reference annotates the call as
   `call dword ptr [eax+48h] ; GameStudioRenderer_StudioRenderModel, vtable offset 0x48`
   (pseudocode `(*((...))self->vtable + 18))(self); // ..., offset 0x48`). The Linux reference
   annotates the same pass at `vtable offset 0x4c` (`self->vtable` index 19).
4. The picked function VA is validated as a function entry; `vfunc_index` is resolved by matching
   it against exactly one entry of the `GameStudioRenderer_vtable` artifact, and `vfunc_sig` is
   copied from the resolved `func_sig`.

## Pitfalls

- This artifact is the **input** of `find-GameStudioRenderer_StudioRenderModel-decompiles`, which
  resolves `GameStudioRenderer_StudioRenderFinal` from its body. A wrong function here propagates
  into StudioRenderFinal.
- On HL-family Linux the method's full entry and its inlined hardware/software children occupy
  distinct vtable slots. Accepting a mislabeled child from `found_vcall` before the correct
  `found_funcptr` produces the wrong function; the index is therefore re-derived from the vtable
  artifact rather than trusted from the response text.
- The reference literal is platform-specific (`0x48` / index 18 on Windows, `0x4c` / index 19 on
  Linux); the artifact index always comes from that platform's vtable lookup, never the literal.
