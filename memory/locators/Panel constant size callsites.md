---
title: Panel constant size callsites
type: note
permalink: goldsrc-vibesignatures/locators/panel-constant-size-callsites
---

# Panel constant size callsites

## Overview

A shared finder emits direct CALL patch artifacts for `vgui2::Panel::SetSize(int, int)` and `vgui2::Panel::SetMinimumSize(int, int)` when both dimensions have the approved constant provenance. The methods are nonvirtual; VFT hooks cannot intercept these calls.

## Responsibilities

- `Const`: two direct constant values, including zero. Applies to old HL/CS/CZ/CZDS, CoF and **all svencoop tags**, including svencoop-10257; never compare unrelated families by numeric build number.
- `ScaledConst`: both dimensions are unmodified returns of the current `Panel::GetProportionalScaledValue(int)` on the same receiver, each with a constant input. Applies to hl-10210 and cstrike/czero/czeror-10210.
- Exclude mixed units, variable inputs, restored sizes, and content/pixel sizes plus scaled margins. The final sizing call must exist; inlined sizing code is not a fictional callsite.

## Involved Files & Symbols

- `ida_preprocessor_scripts/find-vgui2_Panel-size-callsites.py`: single public entry point for engine (hw), gameui, serverbrowser and applicable CS-family client.
- `_panel_size_collect.py`: current-binary method identities and call enumeration.
- `_panel_size_identity.py`: pure provenance, forwarding-wrapper and proportional-helper predicates.
- `_panel_size_callsites_common.py`: exact declared counts, numbering, signature validation and patch writer.
- `_func_to_func_callsites_common.py`: shared direct-call signatures; existing owner/callee finder behavior retained.
- `_vgui_paint_common.py`: shared current-instruction stack-check helper recognition, also used by `_vgui_private_symbols_common.py`.
- Output families: `vgui2_Panel_SetSize_{Const|ScaledConst}_callsite_N` and `vgui2_Panel_SetMinimumSize_{Const|ScaledConst}_callsite_N`, each `category: patch`.

## Architecture

1. Declare the module-local current `vgui2_Panel_Init` input (CS client uses `ClientVGUI_Panel_Init`). Recover the current Panel RTTI table.
2. Intersect exact `Untitled` and `MinimizeToSysTray` string-reference owners to locate the Frame constructor context. Its source `SetMinimumSize(128,66)` statement, scaled in HL25, supplies a candidate. These are source semantic constants, not a filter on the collected callsites.
3. Validate that candidate as a pure `IPanel::SetMinimumSize(GetVPanel(), w, h)` wrapper. Derive GetVPanel from the current Panel table's leaf receiver-member getter. Require parameter forwarding and reject extra setter calls (e.g. SetBounds).
4. Trace Panel::Init's third/fourth explicit parameters to the current IPanel dispatch, deriving SetSize independently of any fixed vtable slot. Recover the unique standalone wrapper that forwards its own two explicit arguments to that interface slot.
5. HL25 additionally verifies the proportional helper's unchanged-input return and two distinct normal/HD scalar interface dispatch paths on the same accessor. No fixed ISchemeManager slot is used.
6. Enumerate callers including resolved ELF PLT paths, trace register/stack provenance, and match the configured mode. Unknown caller analysis is an error; an unknown value does not establish a match.
7. Sort qualifying final CALL addresses in each binary and emit exact-count numbered patches. Signatures identify the current instruction uniquely; `patch_sig_disp=0`, no patch_bytes. The branch displacement is retained in the signature like existing callsite finders; this is current-artifact validation, not cross-version discovery.

## Dependencies

- [[idalib-mcp]] strict restored/no-save owned lifecycle; BLOB inputs use `prepare_analysis_binary` and the established decrypted PE/IDB.
- Shared `_x86_vcall_flow`, RTTI recovery, ELF resolution, patch schema and repository analyzer validation.
- Source intent: `D:/HLND2T_official/vgui2/controls/Panel.cpp` Init, SetSize, SetMinimumSize and `Frame.cpp` constructor. HL25's Panel proportional helper is established by current Windows instructions and matching Linux symbols, not assumed from the older source revision.

## Notes

### ABI provenance pitfalls

Trigger: identical source yields different stack/receiver forms. Root causes: MSVC GetVPanel call metadata can incorrectly consume the pending size arguments; debug builds insert transparent stack checks; Linux can split OnButtonToggled into a private helper whose receiver arrives in EAX.

Correct approach: verify the current GetVPanel and IPanel call arities, normalize only their proven Windows stack cleanup, recognize the current stack-check body's normal and trap paths, and preserve distinct symbolic entry-register identities for caller analysis. Do not treat two unknown receivers as equal. Validation uses synthetic wrong-receiver, modified-result, variable/ambiguous input, stack-spill, register-receiver, repeated-result and extra-forwarding-call cases, plus the actual version matrix. Scope: 32-bit PE/ELF VGUI code.

### Coverage and consumer boundary

Configured coverage is 21 tags / 43 module blocks / 62 binaries. HL/Sven/CoF client modules without an embedded Panel implementation are not forced to match; CS-family configs do not declare separate engine/gameui/serverbrowser modules. Counts are registered only for declared platforms. Verified output inventory is 1,149 artifacts: Windows 766, Linux 383; engine 196, gameui 395, serverbrowser 353, client 205.

Zero SetSize matches in HL25 engine and CS-family client are legitimate under the strict scaled-constant rule; each still has the Frame SetMinimumSize match. The finder verifies both method identities and both counts, including zero. Numbers are binary-local address ordering, not cross-version business identities.

`ScaledConst` labels already-scaled inputs; consumers must not blindly apply a second scale. `Const` identifies provenance, not an assertion that every matched business operation should be scaled. No MetaHookSv consumer migration is included in this finder task.

### hl-10210 ServerBrowser evidence

Windows SHA-256 `0c8dff5862b7e8209cdf9690f49a0bf4e29cc3410e9fb6ee77ed240f428b563c`, image base `0x10000000`: Panel SetSize VA `0x100197e0`, SetMinimumSize `0x10019310`, proportional helper `0x10014ec0`. BaseGamesPage constructor calls at `0x100017bf` and `0x10001d59`, OnButtonToggled `0x10004976`, and ServerBrowserDialog constructor `0x10010752` pass scaled constants. Its minimum-size call is `0x10010731`. The same OnButtonToggled restores existing dimensions at `0x10004a3b`, which is deliberately excluded.

Windows has 4 scaled SetSize / 5 scaled SetMinimumSize calls; Linux has 3 / 6 due to inlining and branch layout. Linux `.part` at `0x306b0` uses a register receiver and contains the matching call at `0x30710`.

## Callers

Future MetaHookSv callsite consumers can redirect selected calls by symbol instead of scanning dimensions or broad method hooks. Existing shared signature consumers and VGUI private-symbol producers retain their contracts.

## Completion verification (2026-10-01)

- Forced owned strict restored/no-save matrix `analysis-batch-20261001T231544-16f92b5410644678b080f76ddcfa82b0`: all 62 binaries succeeded, none failed/skipped.
- Follow-up `analysis-batch-20261001T233008-92810a1723d643c4b0f1004682a43b49`: 17 nodes across 15 binary tasks succeeded, including all HL25 sizing nodes after the ambiguous-receiver guard and existing private-symbol, Panel_Init and callsite-signature consumers. Existing tracked artifacts have no content changes.
- Independent PE/ELF byte audit verified all 1,149 artifact names, VA/RVA arithmetic, CALL destinations, exact signature bytes/uniqueness and address sets against exploratory facts. ELF R_386_PC32/R_386_32 relocations for defined symbols must be applied before comparing loaded-code signatures; raw text relocation addends are not call destinations.
- Unit suite: 1,343 tests OK, 5 skipped. Repository-contract suite: 15 tests OK. Repository format check and staged diff check exit 0.
- Production scripts, configs, artifacts, behavioral tests and this note are deliverables. Probe programs, batch logs and independent audit scripts remain outside the repository.
