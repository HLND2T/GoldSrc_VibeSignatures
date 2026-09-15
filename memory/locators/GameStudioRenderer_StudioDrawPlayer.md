---
title: GameStudioRenderer_StudioDrawPlayer locator
type: note
permalink: goldsrc-vibesignatures/locators/gamestudiorenderer-studiodrawplayer
tags:
  - locator
  - client
  - vfunc
---

# GameStudioRenderer_StudioDrawPlayer

## Symbol

- **Name**: `GameStudioRenderer_StudioDrawPlayer`
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
- Always present. The artifact always carries
  `vfunc_sig_allow_across_function_boundary: true` (declared as a generation option in
  `VFUNC_FIELDS`), because the method can be short or GCC-split.

## Predecessors

- `GameStudioRenderer_StudioDrawModel.<platform>.yaml` — the annotated LLM reference body
  (declared as a **required** dependency in the spec's `dependency_policy`).
- `GameStudioRenderer_vtable.<platform>.yaml` — supplies the resolved `vfunc_index` /
  `vfunc_offset`.

## How it is located

1. The producer runs `preprocess_common_skill` with the six renderer virtuals as `func_names`,
   `func_vtable_relations = (name, "GameStudioRenderer")` for each, and `old_yaml_map=None`
   (no reuse of a previous artifact's signature).
2. Fast paths: `preprocess_func_sig_via_mcp` needs an old artifact, so with `old_yaml_map=None`
   it yields nothing; the declared `xref_strings` recovery is only configured for
   `StudioCalcAttachments` and `StudioSetupBones`. `StudioDrawPlayer` has no string anchor and
   therefore goes through the **LLM_DECOMPILE** spec.
3. The spec uses `prompt/call_llm_decompile.md` with the platform reference
   `references/{gamever}/client/GameStudioRenderer_StudioDrawModel.<platform>.yaml` and
   `expected_result_sections = ["found_vcall", "found_funcptr"]`.
4. The annotated reference marks the slot in both disassembly and pseudocode. The canonical
   hl-10210 Windows reference carries
   `call dword ptr [eax+0Ch] ; GameStudioRenderer_StudioDrawPlayer, vtable offset 0x0c, dead-player model branch`
   and `((... )vtable[3])(self, flags, v20); // GameStudioRenderer_StudioDrawPlayer, offset 0x0c`.
   The corresponding hl-10210 Linux reference annotates
   `call dword ptr [eax+10h] ; GameStudioRenderer_StudioDrawPlayer, vtable offset 0x10, dead-player model branch`
   (`self->vtable` index 4). The call sits in the dead-player model branch of `StudioDrawModel`.
5. The LLM returns the call target; the finder validates it as a function entry, then enriches
   `vfunc_index`/`vtable_name` by matching the picked `func_va` against exactly one entry of
   the `GameStudioRenderer_vtable` artifact (`_enrich_vfunc_from_vtable` requires exactly one
   match) and sets `vfunc_sig` from that function's `func_sig`.

## Pitfalls

- The reference literal is platform-specific (`0x0c` / index 3 on the canonical Windows build,
  `0x10` / index 4 on Linux — the Itanium destructor pair shifts every later slot by one). Never
  carry the Windows literal into a Linux run, and never carry either literal into another game
  family.
- The index written to the artifact is never taken from the reference text — it is looked up in
  the current binary's vtable artifact, which is why the offset literal is only a semantic hint
  for the LLM.
- Do not confuse this outer slot with `GameStudioRenderer__StudioDrawPlayer`: the latter is the
  base player-model method reached through the vtable from this wrapper and has its own producer
  (`find-GameStudioRenderer-inner-player`), only for the CS/CZ family.
- `vfunc_sig_allow_across_function_boundary: true` is always emitted here, unlike
  `GameStudioRenderer_StudioRenderFinal`; a consumer that drops the flag changes runtime
  resolution.
