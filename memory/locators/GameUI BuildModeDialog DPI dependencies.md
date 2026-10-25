---
title: GameUI BuildModeDialog DPI dependencies
type: note
permalink: goldsrc-vibesignatures/locators/game-ui-build-mode-dialog-dpi-dependencies
tags:
- gameui
- vgui2
- issue-407
- abi
---

# GameUI BuildModeDialog DPI dependencies

## Overview

Issue #407 supplies module-local native build-editor gamedata for the downstream VGUI2Extension DPI repair (MetaHookSv/MetaHookSv#954). Coverage is every configured GameUI: 12 tags / 16 PE32-I386 or ELF32-I386 binaries. Native UI hooks and game-runtime layout regression remain downstream work.

## Responsibilities

- Recover complete BuildModeDialog construction, PerformLayout, inherited ApplySchemeSettings, Frame::GetClientArea and Panel::GetVPanel.
- Publish the anonymous add-control ComboBox member and native PanelListPanel enumeration/layout dependencies.
- Preserve actual target signatures, class ownership and sparse item IDs; never use SDK offsetof, fixed vtable slots, child indices or another module's addresses.

## Involved Files & Symbols

- `ida_preprocessor_scripts/find-GameUI-BuildModeDialog.py`: deterministic current-binary collector and artifact writer; no LLM references required.
- `ida_preprocessor_scripts/_buildmode_identity.py`: row-to-ID-to-panel relation and paired item-ID label/panel getters.
- `ida_preprocessor_scripts/_x86_vcall_flow.py`: full-register SHL/SAL and two/three-operand constant IMUL provenance.
- `tests/test_buildmode_identity.py`, `tests/test_x86_vcall_flow.py`: synthetic behavior, moved fields/slots, ambiguous identities, invalid-ID null paths and arithmetic.
- `configs/<tag>.yaml`: authoritative scope, DAG and output platform gates.
- `bin_artifacts/<tag>/gameui/`: 275 new YAML artifacts (179 functions, 80 four-byte members, 16 primary list vtables).
- Existing [[ComboBox Unicode menu identity]] provides `vgui2_BuildModeDialog_SetActiveControl` and BuildModeDialog RTTI; reuse them.
- Semantic source references: `D:/HLND2T_official/vgui2/controls/BuildModeDialog.cpp`, `PanelListPanel.cpp`, `Frame.cpp` and symbol-bearing configured Linux binaries. Newer MetaHook SDK interfaces differ from target GoldSrc.

## Architecture

1. Exact `VGUI Build Mode Editor` owner must install the current BuildModeDialog RTTI table. The `BuildModeControls` + `FileSelectionCombo` owner must be that constructor or its direct this-receiver callee. This identifies the complete constructor, rather than a construction-internal instruction.
2. Identify the file ComboBox constructor by parent/name and its current RTTI assignment. Follow its anonymous instance through the `None` insertion and this-member assignment to recover `m_pAddNewControlCombo`.
3. Reuse current PropertySheet PerformLayout and MessageBox ApplySchemeSettings slots with the current editor/list tables. Verify editor scheme equals the current Frame implementation. Frame client-area identity writes caller output references and obtains dimensions through those same references. GetVPanel is verified through Panel::SetSize forwarding, including GCC devirtualization.
4. Prove GetCellRenderer(row) equals GetItemPanel(sortedIDs[row]); the other getter loads the other pointer from the same DATAITEM. The invalid row path must return null, including an out-of-line bool guard or a merged GCC RET. This identifies logical row count independently of debug allocation-capacity assertions.
5. Native computeVPixelsNeeded walks that same row vector and sums panel heights with the buffer member. Native layout places label/edit siblings at the same y/height and computes edit x from first-column width plus buffer. Both spacing and width come from actual instructions.
6. Early debug CUtl accessors are projected through actual register/stack arguments. Composite offsets lacking one instruction containing the complete displacement have value-only member artifacts; no misleading offset signature is emitted. Other member artifacts include a unique owning-function signature and current instruction displacement.

## Dependencies

- Current-module inputs: `GameUI_PropertySheet_PerformLayout`, `GameUI_MessageBox_ApplySchemeSettings`, `GameUI_Panel_SetSize`.
- Shared RTTI, x86 dataflow, validated function signatures and category writers. Analysis uses exact warm restored IDBs without saving.
- HL/CZ GameUI is separate from CS/CZ client binaries. The separate `cstrikegameui-8684` variant is included; no client address is reused.

## Notes

### Native ABI and consumer contract

- `vgui2_BuildModeDialog_ctor`: `vgui2::BuildModeDialog::BuildModeDialog(vgui2::BuildGroup*)`; Windows thiscall, Linux i386 this as ordinary stack argument. ELF C1/C2 aliases in symbol-bearing references share the observed entry; the finder checks actual constructor ownership/table installation.
- `vgui2_BuildModeDialog_PerformLayout`: native editor override, address plus slot.
- `vgui2_BuildModeDialog_ApplySchemeSettings`: **actual func_name is `vgui2::Frame::ApplySchemeSettings(vgui2::IScheme*)`**. Every configured editor inherits this body. A downstream detour must discriminate the receiver to avoid modifying unrelated Frames.
- `vgui2_Frame_GetClientArea(int&, int&, int&, int&)` and `vgui2_Panel_GetVPanel()` are native virtual methods with address and slot.
- Existing `vgui2_BuildModeDialog_SetActiveControl(vgui2::Panel*)` remains the dynamic row creation/update hook. No duplicate finder/output is added.
- All configured constructors create named `BuildModeControls`, `FileSelectionCombo`, `StatusLabel`, `Divider`, `SaveButton`, `ExitButton`, `ApplyButton`, `VarsButton`, `DeletePanelButton`. These are candidates for downstream VPANEL tree lookup. Their controls-creation paths have exactly one anonymous ComboBox, the exported add-control member. `m_pEditableParents`/`m_pEditableChildren` are not emitted: no such additional anonymous constructor instances are present. Localization/NextChild/PrevChild are not in these creation paths. Do not invent child indices.
- Native `PanelListPanel::GetItemCount()` is **non-const and virtual** in this matrix; GetItemLabel(int), GetItemPanel(int), GetCellRenderer(int), PerformLayout() and computeVPixelsNeeded() are virtual too.
- Native GoldSrc has no usable GetItemIDFromRow interface in this matrix. Use `vgui2_PanelListPanel_m_SortedItems_m_Size` and `_m_pMemory`: read current signed row count and the pointer to a flat int ID array; bounds-check row and read `ids[row]`. Pass that ID to the native validity-checking GetItemLabel/GetItemPanel. Do not pass row as ID, assume IDs stay contiguous after removal, or interpret a plugin CUtl container layout. GetItemCount is the linked-list element count, not a replacement for reading the verified row bound.
- SetVerticalBufferPixels is not a native target here. Use `vgui2_PanelListPanel_m_iPanelBuffer` (four-byte int), then rerun native list layout so computeVPixelsNeeded updates scroll range.
- `vgui2_PanelListPanel_m_iFirstColumnWidth` is available everywhere. `vgui2_PanelListPanel_SetFirstColumnWidth(int)` is additionally exported on HL8684 Linux, HL10210 Linux and Sven8948 Linux. Windows and stripped Sven10257 Linux use the verified field alternative. Lack of a name in stripped Sven10257 does not prove a body is absent; no guessed setter is published.
- Exported list PerformLayout/computeVPixelsNeeded support native layout/scroll recalculation after changing row heights, column width and buffer; outer editor bounds alone cannot permanently override dynamic rows. Pixel sizes and measured font heights must not be scaled twice. Preserve native objects, ownership, BuildGroup, resource coordinates, user settings and lifecycle.

### Observed version matrix (evidence, never finder constants)

| Version/platform | Editor layout / scheme slot | Frame client slot | Add combo | Row memory / count | Buffer / column |
| --- | --- | --- | --- | --- | --- |
| HL3248/3266/3329/3647 Windows | 111 / 79 | 184 | 0x148 | 0x98 / 0xa4 | 0xc0 / 0xb4 |
| HL4554/6153/8684 Windows; cstrikegameui8684 Windows; Sven8948/10257 Windows; CoF5936 Windows | 111 / 79 | 186 | 0x14c | 0x98 / 0xa4 | 0xc0 / 0xb4 |
| HL8684 Linux; Sven8948/10257 Linux | 112 / 80 | 187 | 0x14c | 0x98 / 0xa4 | 0xc0 / 0xb4 |
| HL10210 Windows | 111 / 79 | 186 | 0x154 | 0x9c / 0xa8 | 0xc4 / 0xb8 |
| HL10210 Linux | 112 / 80 | 187 | 0x154 | 0x9c / 0xa8 | 0xc4 / 0xb8 |

### Reusable debugging lessons

- Trigger: early optimized getter loses node-index provenance. Root cause: LEA + SHL or constant IMUL was unsupported in the shared tracer. Correct approach: preserve full-width constant scaling, fail closed on truncated/unknown operands, and compare equivalent arithmetic expressions. Verify with synthetic instruction tests and real HL3248/3266/3329 binaries.
- Trigger: debug getter return is a joined null/pointer expression through multiple helpers. Root constraint: logical size and allocation capacity are separate fields; assertions introduce extra comparisons. Correct approach: project actual helper parameters and prove the row-rejection branch returns null. Verify that native item-ID getters and row renderer select the same DATAITEM.
- Trigger: raw Linux table pointers disagree with IDA values. Root cause: ELF R_386_32 relocations, especially HL8684. Apply symbol/addend relocations before independent raw-file table checks.
- Trigger: strict analyzer refuses an IDB after research. Constraint: original directories retain IDA sidecars. Correct approach: use byte-identical temporary binary and packed-IDB copies, verify SHA-256 before use, keep restored/no-save analysis, and leave original scratch unstaged.

### Verification evidence (2026-10-25)

- Final forced exact batch selects all 16 GameUI nodes; each node reruns the finder and analyzer artifact validation (not an existing-output skip).
- Independent offline audit checked all 275 new artifacts against all 16 binary inputs: source/copy hashes, unique function/member-owner signatures, PE/ELF x86 identity, relocated raw RTTI entries, function VA/RVA arithmetic and index-times-four consistency.
- Final batch `analysis-batch-20261025T184734-9e5fb70736154f639fb2d00dbfbc42be`: 16 succeeded, 0 failed, 0 skipped. Independent audit: 16 inputs / 275 artifacts, all checks passed.
- Full unit run: 1567 tests OK, 12 existing skips. Final `tests/run_test_suite.py all -b --durations 30`: 1586 tests OK, 16 skips (Windows/POSIX differences, opt-in CLI/IDA tests and unavailable Redis). Actual IDA evidence is the successful 16-node analyzer batch, independent of the opt-in test skip.
- `format_repo_files.py --check` and `git diff --cached --check`: exit 0. No concrete finder inventory/config text was frozen in tests.
- Temporary selection/audit/log scripts and binary/IDA copies remain under ignored `.tmp/`; no new runtime/SDK object or plugin hook is implemented here.

## Callers

Downstream VGUI2Extension can consume these artifacts to retain the native BuildModeDialog/BuildGroup and adjust its outer controls and dynamic list rows. Game-runtime acceptance still belongs to the downstream repair: 720p/1080p/1440p/4K, DPI on/off, close/reopen, drag/resize, property changes, dropdowns, scrolling, edit/save and unchanged resource coordinate units.
