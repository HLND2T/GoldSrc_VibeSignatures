---
title: GameUI RichText insertion and CR branch
type: note
permalink: goldsrc-vibesignatures/locators/game-ui-rich-text-insertion-and-cr-branch
tags:
- gameui
- richtext
- locator
- issue-307
---

# GameUI RichText insertion and CR branch

## Overview

Issue #307 extends GameUI's existing condump/Print/ANSI insertion chain with the Unicode insertion overload, the standalone character inserter where the console path actually calls it, and the CR-filter branch locator. Artifact identities use the ELF names `vgui2::RichText::InsertString(wchar_t const*)` and `vgui2::RichText::InsertChar(wchar_t)`, not MetaHookSv's local field spelling.

## Responsibilities

- Reuse current-binary predecessor artifacts; never discover from old output signatures.
- Map direct callees through annotated LLM references, validate actual instructions/arguments and source behavior, and emit unique in-function signatures.
- Locate the CR conditional branch without modifying binary bytes. The patch artifact is a branch locator, not a replacement-byte policy.

## Involved Files & Symbols

- `ida_preprocessor_scripts/find-GameUI-RichText-print-callees.py`: optional ANSI-only output for CoF 5936 / HL 8684 Windows; other six old Windows registrations also retain InsertColorChange.
- `find-GameUI-RichText-wide.py`, `find-GameUI-RichText-char.py`, `find-GameUI-RichText-cr-branch.py` and `_gameui_richtext_common.py`: discovery, independent validation and serialization.
- `_richtext_identity.py`: character provenance, flag-preserving compare/branch association, exclusive line-break update and repaint evidence.
- `_x86_vcall_flow.py:first_pass_blocks`, `_vgui_paint_common.py:flow_at`: opt-in first-iteration provenance. Existing callers retain their full fixed-point trace.
- References: `references/hl-10210/gameui/GameUI_RichText_InsertStringA.{windows,linux}.yaml`; `references/hl-8684/gameui/GameUI_RichText_InsertStringW.{windows,linux}.yaml`.
- Source: `D:/HLND2T_official/vgui2/controls/RichText.cpp:1585-1641`; `gameui/GameConsoleDialog.cpp:226`; MetaHookSv `Plugins/VGUI2Extension/GameUI.cpp:2691-2920` is supporting evidence, not a locator specification.

## Architecture

Existing condump -> Print / ANSI InsertString -> Unicode InsertString -> standalone InsertChar where present -> CR branch. The new functions use `found_call` with current-IDB instruction validation and a body check. The patch path verifies the comparison's scalar argument or character loaded through the string argument, ABI width, branch flags, and that only the non-CR path updates `m_LineBreaks.Count() - 2` and repaints before the next guard evaluation.

The Unicode function also traverses a wide-character stream using the current ABI's character width, invalidates layout with false/false, sets the recalc flag and repaints. Pointer increments may use ADD or same-register LEA. The final function signature is regenerated with a larger, strictly in-function budget; the intermediate common helper signature never becomes the discovery anchor.

## Dependencies

- Existing `CGameConsoleDialog_Print` / `GameUI_RichText_InsertStringA` artifacts and the normal config DAG.
- Owned [[idalib-mcp]] lifecycle and canonical annotated reference generation.
- Shared x86 dataflow, LLM `found_call` validation, function/patch signature uniqueness and formal artifact contracts.

## Notes

- Scope: 11 configured GameUI versions / 15 binaries. Unicode insertion and CR branch cover all 15. Standalone InsertChar is published only for the 10 Windows inputs other than HL 10210. HL 10210 Windows and all four Linux inputs inline character insertion on this console path. Separately retained Linux InsertChar symbols are not evidence that the active string path calls them. CS-family configs have no separate GameUI module; unsupported Linux platforms are not fabricated.
- Windows wchar_t is 2 bytes; Linux is 4. Several shipped filters compare only the low byte with CR. Preserve that instruction behavior rather than imposing the full-width comparison from the source revision. Sven 10257 ELF is stripped: its role comes from current-body/call/dataflow evidence, not a claimed symbol-table name.
- Trigger: CoF Print loads m_pHistory through different scratch registers. Root constraint: register equality does not prove object identity. Correct approach: require the same member load from the same `this` value at both calls. Verification: forced rebuild of all eight ANSI finder registrations; six pre-existing outputs remain unchanged.
- Trigger: repeated pointer increments erase the original string argument in fixed-point value flow. Correct approach: cut DFS backedges for first-iteration provenance, retain the full CFG for guard reachability, and separately validate the loop's actual width/increment. This restricted trace must never be treated as proof of subsequent-iteration values. Synthetic tests cover loops whose first condition lies after the body and diamond joins.
- The `-2` invariant is a count of line breaks from the source statement, not a byte displacement or wchar_t width. Unknown/ambiguous updates fail closed.
- Trigger: HL 3266/3329 debug prologues share the default 24 fixed signature bytes. Correct approach: retain callee-based discovery, increase output-signature inspection and require a unique signature entirely within the target function. Do not add another discovery byte pattern for each debug build.
- Trigger: MCP disconnect after the shared LLM helper writes its intermediate YAML. Correct approach: remove that task-owned intermediate in `finally` unless all validation and final serialization succeeded; the existing-output optimization must not mistake an unvalidated file for a finished artifact. A synthetic transport-failure test reproduces the old leak.
- Verification: force the exact registered nodes per tag (`-gamever TAG -oldgamever none -node gameui:PLATFORM:SKILL`), since `-allgamever -skill` stops at versions without that skill. The new chain is 40 nodes; ANSI regression is eight. Independently compare the 42 added artifacts with the raw binaries, unique signature matches and surveyed identities. Run unit / repository-contract / formatting gates; stage new artifacts before the tracked-inventory contract check.

## Callers

- `CGameConsoleDialog::Print(char const*)` -> `vgui2::RichText::InsertString(char const*)`.
- ANSI insertion forwards localization results or the converted Unicode buffer to `vgui2::RichText::InsertString(wchar_t const*)`.
- Only the non-inline Windows loops call `vgui2::RichText::InsertChar(wchar_t)`.
