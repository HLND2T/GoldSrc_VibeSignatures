---
title: GameStudioRenderer_StudioSaveBones locator
type: note
permalink: goldsrc-vibesignatures/locators/gamestudiorenderer-studiosavebones
tags:
  - locator
  - client
  - vfunc
---

# GameStudioRenderer_StudioSaveBones

## Symbol

- **Name**: `GameStudioRenderer_StudioSaveBones`
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
   `func_vtable_relations = ("GameStudioRenderer_StudioSaveBones", "GameStudioRenderer")`.
2. No `xref_strings` anchor is declared for this target (unlike `StudioCalcAttachments` /
   `StudioSetupBones`), and with `old_yaml_map=None` the signature fast path yields nothing —
   so discovery always runs through the `LLM_DECOMPILE` spec.
3. The spec uses `prompt/call_llm_decompile.md` against the required reference
   `references/{gamever}/client/GameStudioRenderer_StudioDrawModel.<platform>.yaml`, with
   `expected_result_sections = ["found_vcall", "found_funcptr"]`. The canonical hl-10210 Windows
   reference annotates the slot as
   `call dword ptr [eax+20h] ; GameStudioRenderer_StudioSaveBones, vtable offset 0x20`
   (pseudocode `(*((...))self->vtable + 8))(self); // ..., offset 0x20`). The Linux reference
   annotates the devirtualized form
   `cmp eax, offset _ZN20CStudioModelRenderer15StudioSaveBonesEv; ... vtable offset 0x24`
   (`self->vtable` index 9, marked `devirtualization guard`).
4. The picked function VA is validated as a function entry, then `vfunc_index` is resolved by
   matching it against exactly one entry of the `GameStudioRenderer_vtable` artifact;
   `vfunc_sig` is copied from the resolved `func_sig`.

## Pitfalls

- SaveBones shares its bone-name string family with `MergeBones` / `SetupBones`, and the two
  neighbours are called a few instructions apart in the annotated `StudioDrawModel` body. The
  LLM must be pointed at the specific slot annotation — accepting a nearby sibling call yields a
  plausible but wrong function, and only the exact-one-entry vtable match rejects it.
- The reference literal is platform-specific (`0x20` / index 8 on Windows, `0x24` / index 9 on
  Linux) and the Linux form is a devirtualization guard (`cmp reg, offset`), so the correct
  answer there is a `found_funcptr`; the slot still comes from the vtable artifact lookup.
- The optimized client SaveBones can reference the first cached bone name's trailing byte rather
  than its start, so a search for the exact literal's start would miss it — this is exactly why
  this target relies on the annotated predecessor body instead of a string xref.
