---
title: Panel OnSizeChanged chain
type: note
permalink: goldsrc-vibesignatures/locators/panel-on-size-changed-chain
---

# Panel OnSizeChanged chain

## Overview

Issue #342 locates the VGUI size-change chain IPanel::SetSize -> VPanelWrapper -> VPanel::SetSize -> IClientPanel::OnSizeChanged, the GameUI Panel/EditablePanel overrides, and two direct calls inside EditablePanel::OnSizeChanged. Every slot is derived from current-binary dataflow; no ABI slot is inherited across platforms.

## Involved Files & Symbols

- `ida_preprocessor_scripts/find-vgui2_IPanel_SetSize.py` (gameui): reuses `_panel_size_collect.IDENTIFY`; Panel::Init's 3rd/4th args and the unique Panel::SetSize wrapper prove `sizeslot`. Emits slot-only `vgui2_IPanel_SetSize`.
- `ida_preprocessor_scripts/find-vgui2_VPanel_SetSize.py` (vgui2): VPanelWrapper entry at that slot must forward `(vguiPanel, wide, tall)` to one VPANEL slot -> `vgui2_VPanel_SetSize`; inside it the unique vcall on the current `VPanel::Client` result (or its returned member when Linux inlines Client) -> slot-only `vgui2_IClientPanel_OnSizeChanged`.
- `ida_preprocessor_scripts/find-GameUI-OnSizeChanged.py` (gameui): RTTI `vgui2_Panel_vtable` / `vgui2_EditablePanel_vtable`, INHERIT_VFUNCS from `../vgui2/vgui2_IClientPanel_OnSizeChanged`, then patches `vgui2_EditablePanel_OnSizeChanged_call_{GetChild,SetBounds}_callsite_0`.
- `_panel_bounds_collect.IDENTIFY_BOUNDS` + `_panel_bounds_callsites_common.bounds_identity_source(tail)`: shared SetBounds proof; optional `values["bounds_owner"]` restricts candidates to one caller's direct callees.

## Architecture

1. gameui IPanel SetSize slot -> vgui2 (cross-module input `../gameui/...`) -> gameui (input `../vgui2/...`). The planner orders the cross-module DAG edges.
2. EditablePanel override must directly call Panel::OnSizeChanged and differ from it.
3. SetBounds = the single direct callee of the override passing `bounds_body_matches`; exactly one call.
4. GetChild = direct call whose result is SetBounds' receiver, made on `this` (Windows: callee `retn 4`); exactly one call. Patch signatures start at the CALL, `patch_sig_disp=0`.

## Notes

### Evidence (hl-10210)

- IPanel::SetSize: Windows +0x10 (idx 4), Linux +0x14 (idx 5). VPanel::SetSize: Windows `vgui2.dll 0x100167f0` idx 12, Linux `vgui2.so 0x17410` idx 13. IClientPanel::OnSizeChanged +0x24 (idx 9) on both; Panel/EditablePanel primary tables share index 9.
- GameUI Windows: Panel::OnSizeChanged `0x1004b4c0`, EditablePanel `0x10052220`, GetChild call `0x10052273`, SetBounds call `0x10052346`. Linux: `0xf4b60` / `0xd1c60`, GetChild `0xf8400` call `0xd1cd7`, SetBounds `0xf7660` call `0xd1dec`.

### Pitfalls

- Trigger: VPanel::SetSize notify not unique. Root cause: CMOVcc clamping leaves size args unknown. Approach: prove the receiver only.
- Trigger: GetChild check fails on Windows. Root cause: loop index merges to unknown. Approach: require receiver `this` plus callee RET purge.
- Trigger: Linux walk timed out (60 s) in full SetBounds candidate scan. Approach: `bounds_owner` scoping; identity proof unchanged.
- hl-3248..cof Windows-only tags and hl-8684/svencoop need warmed vgui2 IDBs (`warmup_idb.py -python <idalib python>`).
