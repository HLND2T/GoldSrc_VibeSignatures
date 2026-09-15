---
title: GameStudioRenderer_StudioMergeBones locator
type: note
permalink: goldsrc-vibesignatures/locators/gamestudiorenderer-studiomergebones
tags:
  - locator
  - client
  - vfunc
---

# GameStudioRenderer_StudioMergeBones

## Symbol

- **Name**: `GameStudioRenderer_StudioMergeBones`
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

1. `preprocess_common_skill` with this name in `func_names` and
   `func_vtable_relations = ("GameStudioRenderer_StudioMergeBones", "GameStudioRenderer")`.
2. No `xref_strings` anchor is declared, and `old_yaml_map=None` disables the signature fast
   path, so the target is always resolved by the `LLM_DECOMPILE` spec.
3. The spec uses `prompt/call_llm_decompile.md` against the required reference
   `references/{gamever}/client/GameStudioRenderer_StudioDrawModel.<platform>.yaml`, with
   `expected_result_sections = ["found_vcall", "found_funcptr"]`. The canonical hl-10210 Windows
   reference annotates the call as
   `call dword ptr [edx+24h] ; GameStudioRenderer_StudioMergeBones, vtable offset 0x24`
   (pseudocode `((void (__thiscall *)(...))v10[9])(self, self->m_pRenderModel); // ..., offset 0x24`).
   The Linux reference annotates the same method at `vtable offset 0x28` (`self->vtable` index 10).
4. The picked function VA is validated as a function entry; `vfunc_index` is resolved by
   matching it against exactly one `GameStudioRenderer_vtable` entry, and `vfunc_sig` is copied
   from the resolved `func_sig`.

## Pitfalls

- IDA can render the annotated call without whitespace before the comment
  (`call target;comment`). The target-text validation strips semicolons outside quoted literals;
  an older strip required whitespace and this is the HL-10210 Windows MergeBones locator that
  originally failed because of it. Preserve the reference annotations verbatim.
- MergeBones / SaveBones / SetupBones use the same bone-name literal family and are invoked
  within a few instructions of each other, so a wrong-sibling selection is the dominant failure
  mode; the exact-one-entry vtable match is the gate.
- The reference literal is platform-specific (`0x24` / index 9 on Windows, `0x28` / index 10 on
  Linux); the artifact index always comes from that platform's vtable lookup, never the literal.
