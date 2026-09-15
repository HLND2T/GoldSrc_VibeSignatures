---
title: GameStudioRenderer_StudioRenderFinal locator
type: note
permalink: goldsrc-vibesignatures/locators/gamestudiorenderer-studiorenderfinal
tags:
  - locator
  - client
  - vfunc
---

# GameStudioRenderer_StudioRenderFinal

## Symbol

- **Name**: `GameStudioRenderer_StudioRenderFinal`
- **Category**: `vfunc`
- **Module**: client (`client.dll` / `client.so`)
- **Producer**: `ida_preprocessor_scripts/find-GameStudioRenderer_StudioRenderModel-decompiles.py`

## Availability

- Declared in 14 client configs: cstrike-3248/3647/4554/6153/8684/10210, czero-8684/10210,
  czeror-8684/10210, hl-8684/10210, cof-5936, svencoop-10257.
- Platforms: Windows + Linux only where the client module ships a Linux half — cstrike-10210,
  cstrike-6153, cstrike-8684, hl-10210, hl-8684, svencoop-10257. The other 8 configs
  (cof-5936, cstrike-3248/3647/4554, czero-8684/10210, czeror-8684/10210) declare only
  `module_windows: client.dll`, so those runs are Windows-only.
- Always present. Unlike the DrawModel family, `VFUNC_FIELDS` here does **not** declare
  `vfunc_sig_allow_across_function_boundary:true`, so the artifact only carries the flag if the
  resolved body itself requires it.

## Predecessors

- `GameStudioRenderer_StudioRenderModel.<platform>.yaml` — the annotated reference body and the
  required dependency of the LLM spec.
- `GameStudioRenderer_vtable.<platform>.yaml` — supplies `vfunc_index` / `vfunc_offset`.

## How it is located

1. `preprocess_common_skill` with `func_names = ["GameStudioRenderer_StudioRenderFinal"]` and
   `func_vtable_relations = ("GameStudioRenderer_StudioRenderFinal", "GameStudioRenderer")`,
   `old_yaml_map=None`; no `xref_strings` and no `func_xrefs` are declared, so discovery always
   goes through the `LLM_DECOMPILE` spec.
2. Spec: prompt `prompt/call_llm_decompile.md` against the required reference
   `references/{gamever}/client/GameStudioRenderer_StudioRenderModel.<platform>.yaml`
   (`dependency_policy: required`), with
   `expected_result_sections = ["found_vcall", "found_funcptr"]`.
3. The canonical hl-10210 Windows reference annotates the slot as
   `call dword ptr [eax+4Ch] ; GameStudioRenderer_StudioRenderFinal, vtable offset 0x4c` and
   states in the pseudocode block:
   `// GameStudioRenderer_StudioRenderFinal is self->vtable[19], byte offset 0x4c, in all three render passes below.`
   The hl-10210 Linux reference instead annotates three devirtualization guards
   (`cmp eax, offset _ZN20CStudioModelRenderer17StudioRenderFinalEv`) and states
   `// GameStudioRenderer_StudioRenderFinal is self->vtable[20], byte offset 0x50. The comparisons identify its full entry before GCC inlines hardware/software dispatch.`
   The method is reached from the tail of `StudioRenderModel`, which must first be recovered —
   hence the dependency edge on that artifact.
4. The picked function VA is validated as a function entry; `vfunc_index` is resolved by matching
   it against exactly one entry of the `GameStudioRenderer_vtable` artifact and `vfunc_sig` is
   copied from the resolved `func_sig`.

## Pitfalls

- **Do not trust the response text's slot**: on HL-family Linux the full `StudioRenderFinal`
  entry and its inlined hardware/software children are distinct vtable slots. A mislabeled child
  returned as `found_vcall` before the correct `found_funcptr` yields the wrong function; the
  vtable lookup (exactly one matching entry) is the gate, and a candidate with no unique match
  fails closed.
- The reference literals are platform-specific (`self->vtable[19]` / `0x4c` on Windows,
  `self->vtable[20]` / `0x50` on Linux — the Itanium destructor pair shifts later slots by one).
  Neither is portable; the artifact index always comes from that platform's vtable lookup.
- On Linux the reference's own annotation warns `do not select the inlined hardware/software
  child slots`; both `found_vcall` and `found_funcptr` sections are accepted, so only the vtable
  entry match decides.
- Called from three render passes in the same body; repeated references to the same target are
  benign, but a different target picked for one pass must be rejected rather than averaged.
