---
title: GameStudioRenderer_StudioSetupBones locator
type: note
permalink: goldsrc-vibesignatures/locators/gamestudiorenderer-studiosetupbones
tags:
  - locator
  - client
  - vfunc
---

# GameStudioRenderer_StudioSetupBones

## Symbol

- **Name**: `GameStudioRenderer_StudioSetupBones`
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

- `GameStudioRenderer_StudioDrawModel.<platform>.yaml` (required reference, also the string-xref
  fallback owner).
- `GameStudioRenderer_vtable.<platform>.yaml` — supplies `vfunc_index` / `vfunc_offset`.

## How it is located

1. `preprocess_common_skill` with this name in `func_names` and
   `func_vtable_relations = ("GameStudioRenderer_StudioSetupBones", "GameStudioRenderer")`.
2. **First anchor (declared string):** the target-owned bone-name literal
   `FULLMATCH:Bip01 Spine`, resolved through `preprocess_func_xrefs_via_mcp` on the method.
3. **Fallback:** the `LLM_DECOMPILE` spec — `prompt/call_llm_decompile.md` against the required
   reference `references/{gamever}/client/GameStudioRenderer_StudioDrawModel.<platform>.yaml`
   with `expected_result_sections = ["found_vcall", "found_funcptr"]`. The canonical hl-10210
   Windows reference annotates
   `call dword ptr [edx+18h] ; GameStudioRenderer_StudioSetupBones, vtable offset 0x18`
   (pseudocode `v10[6])(self); // GameStudioRenderer_StudioSetupBones, offset 0x18`); the Linux
   reference annotates the same method at `vtable offset 0x1c` (`self->vtable` index 7).
4. The picked function VA is validated as a function entry; `vfunc_index` is resolved by
   matching it against exactly one `GameStudioRenderer_vtable` entry, and `vfunc_sig` is copied
   from the resolved `func_sig`.

## Pitfalls

- `Bip01 Spine` and the sibling bone-name strings are the same literal family the SaveBones /
  MergeBones methods use, so a naive string xref can converge on the wrong sibling. The gate is
  the vtable lookup: two different methods can never map to the same index, and a candidate that
  does not match exactly one entry is rejected.
- GCC can move the literal into a cold clone (`.part.N`) outside the vtable method, which is why
  the verified `GameStudioRenderer_StudioDrawModel` reference body is the fallback anchor.
- The reference literal is platform-specific (`0x18` / index 6 on Windows, `0x1c` / index 7 on
  Linux); the artifact index always comes from that platform's vtable lookup, never the literal.
