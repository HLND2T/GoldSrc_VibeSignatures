---
title: GameStudioRenderer_StudioCalcAttachments locator
type: note
permalink: goldsrc-vibesignatures/locators/gamestudiorenderer-studiocalcattachments
tags:
  - locator
  - client
  - vfunc
---

# GameStudioRenderer_StudioCalcAttachments

## Symbol

- **Name**: `GameStudioRenderer_StudioCalcAttachments`
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
   `func_vtable_relations = ("GameStudioRenderer_StudioCalcAttachments", "GameStudioRenderer")`.
2. **First anchor (declared string):** the target-owned diagnostic
   `FULLMATCH:Too many attachments on %s\n`, looked up by `preprocess_func_xrefs_via_mcp`.
   The literal is tried on the method itself.
3. **Fallback:** the `LLM_DECOMPILE` spec — prompt `prompt/call_llm_decompile.md` against the
   required reference `references/{gamever}/client/GameStudioRenderer_StudioDrawModel.<platform>.yaml`,
   with `expected_result_sections = ["found_vcall", "found_funcptr"]`. The canonical hl-10210
   Windows reference annotates the call as
   `call dword ptr [eax+1Ch] ; GameStudioRenderer_StudioCalcAttachments, vtable offset 0x1c`
   (pseudocode `(*((...))self->vtable + 7))(self); // ..., offset 0x1c`); the Linux reference
   annotates `cmp eax, offset _ZN20CStudioModelRenderer21StudioCalcAttachmentsEv ; ... vtable offset 0x20; not the cold diagnostic clone`
   (`self->vtable` index 8) — GCC devirtualizes this call into an address comparison.
4. The picked function VA is validated as a function entry and its `vfunc_index` is resolved by
   matching it against exactly one entry of the `GameStudioRenderer_vtable` artifact; `vfunc_sig`
   is copied from the resolved `func_sig`.

## Pitfalls

- GCC may outline the `Too many attachments on %s\n` diagnostic into a cold clone outside the
  vtable method, so the string xref alone can name the clone. The Linux reference says so
  explicitly (`not the cold diagnostic clone`) and the reference-body fallback is the corrective
  path: the annotation lives on the verified full method inside
  `GameStudioRenderer_StudioDrawModel`, not on the clone.
- The xref string is the *diagnostic* emitted by the method; it is an anchor, not proof of the
  vtable slot. The slot always comes from the vtable artifact lookup (requires exactly one
  matching entry — two methods sharing an address would fail closed).
- The reference literal is platform-specific (`0x1c` / index 7 on Windows, `0x20` / index 8 on
  Linux); neither is portable across ABIs or game families.
- On Linux the call is devirtualized into `cmp eax, offset CStudioModelRenderer::StudioCalcAttachments`,
  so the correct answer is a `found_funcptr`, not a `found_vcall`; both sections are accepted by
  the spec.
