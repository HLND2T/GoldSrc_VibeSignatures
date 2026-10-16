---
title: ComboBox Unicode menu identity
type: note
permalink: goldsrc-vibesignatures/combo-box-unicode-menu-identity
tags:
- vgui2
- combobox
- abi
- issue-374
---

# ComboBox Unicode menu identity

## Overview
Issue #374 adds module-local gamedata for the Unicode ComboBox hook planned in MetaHookSv/VGUI2Extension#9. Finder identities come from current x86 binary control/data flow and RTTI tables; the downstream plugin repair is separate.

## Responsibilities
- Final hook/call targets: `vgui2::ComboBox::AddItem(char const*, KeyValues const*)`, `AddItem(wchar_t const*, KeyValues const*)`, `GetMenu()`, and the four-argument `vgui2::Menu::AddMenuItem(char const*, KeyValues*, vgui2::Panel*, KeyValues const*)`.
- Intermediate evidence: BuildModeDialog::SetActiveControl, Label::SetText(char const*), SetTextColorState(EColorState), SetContentAlignment(Alignment), ComboBox::m_pDropDown, CSpectatorGUI::UpdateSpectatorPlayerList, ComboBox::IsItemIDValid(int), and UpdateItem(int, wchar_t const*, KeyValues const*).
- Early Windows builds use `vgui2::KeyValues`; the current KeyValues RTTI artifact determines the namespace. ELF function names are checked against the actual demangled overload.

## Involved Files & Symbols
- `ida_preprocessor_scripts/find-GameUI-ComboBox.py`: GameUI entry point.
- `ida_preprocessor_scripts/find-client-ComboBox-Unicode.py`: CS/CZ client entry point.
- `ida_preprocessor_scripts/_combobox_unicode_common.py`: current-IDB collection and validated emission.
- `ida_preprocessor_scripts/_combobox_unicode_identity.py`: receiver, argument, result and branch predicates.
- `tests/test_combobox_unicode_identity.py`: synthetic identity behavior, including moved slots, wrong arguments, nullable messages and loop backedges.
- `bin_artifacts/<tag>/<module>/*.windows.yaml` / `*.linux.yaml`: final VA/RVA, unique signatures, current virtual slots and member locator.
- Source references consulted: `D:/HLND2T_official` VGUI controls and spectator code; `D:/MetaHookSv/MetaHook/include/vgui_controls/ComboBox.cpp`, `ComboBox.h`, `Menu.cpp`, `Menu.h`. Binary evidence remains authoritative.

## Architecture
GameUI: exact `autoresize` and `localize` -> one BuildModeDialog owner -> constructed ComboBox narrow insertion -> original SetText/text message, receiver, userData and returned Menu item ID -> current dropdown field and four-argument Menu dispatch. The wide overload consumes the Unicode conversion's local output while its message retains the original wide argument. A unique pure getter returns that same current dropdown field.

Client: exact `#Spec_PlayerItem_Team` and `UserData` -> one spectator owner -> current original virtual entry -> valid-ID guard on one ComboBox receiver -> update on the nonzero arm and wide insertion on the zero arm. Both arms share text/userData. The selected AddItemW body is independently checked against the client's own narrow insertion/Menu evidence. Client slots or addresses are never copied into GameUI.

The anchor literals each occur once in all applicable inputs; their owning-function intersection is unique. SetText/text and control-label evidence is matched by literal value and proven call data flow, not by call ordinal.

## Dependencies
- Existing `find-GameUI-Menu` output supplies the declared GameUI Menu DAG input. Its whole table is compared with current-IDB RTTI before consumption.
- Current module KeyValues RTTI: `KeyValues_vtable` for GameUI and `ClientVGUI_KeyValues_vtable` for client.
- Shared x86 trace, current RTTI lookup and unique function signature writers; IDA/Hex-Rays supplies supplemental operand evidence for dynamic Linux buffers.

## Notes
- Trigger: a spectator string anchor lands in an ELF `.part.*` body. Constraint: that body can take this in EAX rather than the public cdecl argument position. Correct approach: recover the current table's original entry and project the actual forwarding CALL/JMP register and stack state. Emit the original virtual entry, not the clone.
- Trigger: MSVC virtual CALLs appear to take too few or too many parameters. Constraint: IDA can infer an incorrect stack purge, and SEH chunks add unrelated returns. Correct approach: derive reachable ret cleanup from the current ComboBox target and current Menu/direct tail forwarding; retrace only the guarded receiver's calls. Validation: CS/CZ 10210 Windows and the entire client matrix.
- Trigger: GCC aligns an alloca buffer with AND. Constraint: the small tracer may lose the pointer and Hex-Rays may infer an incomplete call prototype. Correct approach: bind actual outgoing stores for conversion and Menu to one callee-saved register, verify its stack-derived LEA/alignment definition and reject intervening writes; otherwise compare local CTree aliases with complete cdecl argument counts. Validation: Sven 8948 Linux plus all other declared Linux binaries.
- Windows spectator entry belongs to `CSpectatorGUI_vtable2`, checked through the current positive MSVC COL adjustment and class type descriptor. Linux original entry belongs to the primary `CSpectatorGUI_vtable`.
- No SDK slot order, fixed layout, version number, RVA or prior artifact signature participates in discovery. Multiple candidate identities or unknown provenance fail closed. AddItem must return the complete integer item ID; unlike a bool guard, a narrowed return is not accepted.
- Function address/signature and virtual index/offset are emitted together. All table pointers are 4 bytes and every vfunc offset equals index * 4. Member offset comes from a verified AddItemA instruction and is corroborated by GetMenu.
- Coverage: GameUI Windows hl-{3248,3266,3329,3647,4554,6153,8684,10210}, svencoop-{8948,10257}, cof-5936; Linux hl-{8684,10210}, svencoop-{8948,10257}. Client Windows cstrike-{3248,3647,4554,6153,8684,10210}, czero-{8684,10210}, czeror-{8684,10210}; Linux cstrike-{6153,8684,10210}, czero-{8684,10210}, czeror-{8684,10210}. Totals: 21 tags, 32 binary/platform nodes, 282 generated YAMLs.
- Boundaries: undeclared Linux platforms are not fabricated; non-CS clients do not use the spectator anchor. CS/CZ configs do not declare a separate GameUI module, so their GameUI gamedata remains under the configured HL tags. BLOB CS 3248/3647 clients are analyzed through current decrypted PE32 inputs. No selected target is missing or forcibly matched; inlined PlayerAddItem helpers and compiler clones are handled as evidence.
- Sessions: initial research used the shared 13337 supervisor, exact-IDB reuse where active and owned idb_open workers elsewhere. Owned research workers were closed with save=True; external sessions were not saved or closed. Binary SHA-256 was independently checked against each source file. Analyzer validation used byte-identical temporary binary/packed-IDB copies because original research directories retained unpacked IDA lock sidecars; analyzer workers used strict restored/no-save lifecycles and were finalized by the analyzer.
- Validation: full 32-node bounded analyzer matrix; all 282 artifact identities, table entries, VA/RVA, index/offset and source/copy hashes audited; 1508 unit tests (12 existing skips), 15 repository-contract tests and repository format check passed. An independent read-only review found no demonstrable wrong-output defect; current Menu input and CTree arity checks were subsequently tightened.
- Research IDBs remain at `bin/<tag>/<module>/<actual binary>.i64`; binary/IDA scratch is excluded from the delivery. Per-symbol final locations are in the committed artifacts.

### Validated input hashes (2026-10-13)
The BLOB client hashes below describe the decrypted PE actually analyzed.

| Version | Module | Platform | Input SHA-256 | Final original IDB UTC mtime | Initial research finalization |
| --- | --- | --- | --- | --- | --- |
| cof-5936 | gameui | windows | `8255926f84eaa08e9096f2f78dea7f2827c3733e7af8f4408efa0b423acca838` | 2026-10-13 01:14:22 UTC | idb_close(6352abd5), saved=True |
| cstrike-10210 | client | windows | `b434b1c09b10b011be6c42e4154955da0c3ca46e95746988ebea1aa316a2a9f2` | 2026-10-13 01:56:11 UTC | idb_close(05450b4d), saved=True |
| cstrike-10210 | client | linux | `2e799ef31931c0f4372ff31ad30f0aab529b16461ed3b0928dfbd958183b2e5a` | 2026-10-13 01:16:44 UTC | idb_close(68f7f991), saved=True |
| cstrike-3248 | client | windows | `2bc13327c5324a79872d36508d80db7c9ef74af925d50ebc9d1b45b6aef6ef7b` | 2026-10-13 01:16:18 UTC | idb_close(20959f6e), saved=True |
| cstrike-3647 | client | windows | `2bc13327c5324a79872d36508d80db7c9ef74af925d50ebc9d1b45b6aef6ef7b` | 2026-10-13 01:16:19 UTC | idb_close(531eec87), saved=True |
| cstrike-4554 | client | windows | `733d4b48a64991d2cd2a60c20d99f72b6533cc401c47f97cc0e6073bd482b6dc` | 2026-10-13 01:16:22 UTC | idb_close(9cd00757), saved=True |
| cstrike-6153 | client | windows | `221f4c8f8eb6348f90c72c11c252fcf0024d3b3032e503cfab80b3f4c5bee841` | 2026-10-13 01:16:23 UTC | idb_close(3a3bb08a), saved=True |
| cstrike-6153 | client | linux | `0d379680b7545ed352a696539a8049432651edb7056efbf2ce8354347d0feded` | 2026-10-13 01:16:40 UTC | idb_close(19e4dc84), saved=True |
| cstrike-8684 | client | windows | `ef7a0f40989cb79ba95d40f528534da36866892ee871147ca82e133b7a5edc3d` | 2026-10-13 01:45:19 UTC | idb_close(fb46da6c), saved=True |
| cstrike-8684 | client | linux | `40283f3e0c4b6bd21f9281304957ab93c04c60ce5f3d2794cdaf58b3c11ab798` | 2026-10-13 01:32:20 UTC | external session left untouched |
| czero-10210 | client | windows | `b434b1c09b10b011be6c42e4154955da0c3ca46e95746988ebea1aa316a2a9f2` | 2026-10-13 01:16:31 UTC | idb_close(c93f7139), saved=True |
| czero-10210 | client | linux | `2e799ef31931c0f4372ff31ad30f0aab529b16461ed3b0928dfbd958183b2e5a` | 2026-10-13 01:16:51 UTC | idb_close(ccb6096e), saved=True |
| czero-8684 | client | windows | `b017e06a5551f3db8c7c817b72a65433362d8b3c8394edb02cac919528e3f73c` | 2026-10-13 01:16:30 UTC | idb_close(a6d268c3), saved=True |
| czero-8684 | client | linux | `40283f3e0c4b6bd21f9281304957ab93c04c60ce5f3d2794cdaf58b3c11ab798` | 2026-10-13 01:16:48 UTC | idb_close(b4ef0ba0), saved=True |
| czeror-10210 | client | windows | `7eccfa2fd50e391dfeca4ada44110b5e6336523f9d5dd1433f043a0daecbb584` | 2026-10-13 01:16:36 UTC | idb_close(b5716d05), saved=True |
| czeror-10210 | client | linux | `37933b1a6afa92c584b4a0b01cc93401317c288bce0eee268d45035ce5ab9890` | 2026-10-13 01:16:56 UTC | idb_close(eb32d596), saved=True |
| czeror-8684 | client | windows | `e28ef031c1810a913227fbdf8075a367a60165d209b8071a94020a448ff76286` | 2026-10-13 01:16:34 UTC | idb_close(112135c9), saved=True |
| czeror-8684 | client | linux | `515bf1bc95ae8ec161cb99a2d25f53efe0744375dde85879b567710074844971` | 2026-10-13 01:16:53 UTC | idb_close(965c66a9), saved=True |
| hl-10210 | gameui | windows | `b9b8c0c36bd19681627001c06ce2a15496da06b72315d561a12a3964e0265811` | 2026-10-13 01:35:47 UTC | idb_close(6aa2d0cf), saved=True |
| hl-10210 | gameui | linux | `6473a660d1f10c0de35c80fd328110266bb5eeb5d1d7eb07697a4867eda2ce0a` | 2026-10-13 01:31:31 UTC | external session left untouched |
| hl-3248 | gameui | windows | `2f1424c3e9a471c5b92d42aaaad6e63227fd6af5967915482c48c75028a8ced9` | 2026-10-13 01:13:56 UTC | idb_close(e8a57c65), saved=True |
| hl-3266 | gameui | windows | `384449b55753370586619b6908d178b4151bbef86eda0833310dea6aa1384c6a` | 2026-10-13 01:13:59 UTC | idb_close(cf05de41), saved=True |
| hl-3329 | gameui | windows | `384449b55753370586619b6908d178b4151bbef86eda0833310dea6aa1384c6a` | 2026-10-13 01:14:02 UTC | idb_close(e9da2818), saved=True |
| hl-3647 | gameui | windows | `b3588b7ca8f25c70cb062dc12f680e2e8abd75d271026d6e219055fe03a7b172` | 2026-10-13 01:14:05 UTC | idb_close(970f96e5), saved=True |
| hl-4554 | gameui | windows | `5359ffc4589711c625f88ba717391a05cfa91ce273e580a26e27298ad91f38ec` | 2026-10-13 01:14:07 UTC | idb_close(c5c96955), saved=True |
| hl-6153 | gameui | windows | `0c43c0c20f33c5d79fe48e3fa0fefcf37f626ce5a74581a1048171dbf000c10b` | 2026-10-13 01:14:10 UTC | idb_close(e1771355), saved=True |
| hl-8684 | gameui | windows | `684fb5615f0c3ab7d07fcf5503eb214d064c70e25eb0eb22bbf043b4d73c162f` | 2026-10-13 01:14:12 UTC | idb_close(29af8ee0), saved=True |
| hl-8684 | gameui | linux | `fa1ff86540bd216d4d280bf18c02d8835fb7bfad5e58c8f17028bbb40b97cd74` | 2026-10-13 01:14:25 UTC | idb_close(a67bae40), saved=True |
| svencoop-10257 | gameui | windows | `99382b87319d21139c0675d8a45669d64ef930f9e43dbd582461575383545f75` | 2026-10-13 01:14:20 UTC | idb_close(239ea0d8), saved=True |
| svencoop-10257 | gameui | linux | `7bd0deabeb1ff8537c144043d0ba591587fb3e3090d14c6b18ffe14b511e3c39` | 2026-10-13 01:14:31 UTC | idb_close(e7110b1f), saved=True |
| svencoop-8948 | gameui | windows | `0f653d41010add218b1baeea57ffaeb9875eba1cc78157bc0cf17d300a90a524` | 2026-10-13 01:14:17 UTC | idb_close(3b3cbf40), saved=True |
| svencoop-8948 | gameui | linux | `b0eb4ecdc1d79853ba159346b824fc9b7665e8aae75cb5d51330084be273b6e3` | 2026-10-13 02:02:16 UTC | idb_close(03b1a374), saved=True |

## Callers
- vgui2::BuildModeDialog::SetActiveControl -> narrow ComboBox insertion and Label methods.
- CSpectatorGUI::UpdateSpectatorPlayerList (or its current out-of-line PlayerAddItem helper) -> valid-ID test, wide update and wide insertion.


## Client repair dependencies (2026-10-16)

- Trigger: VGUI2Extension needs client-module Menu dispatch for the spectator AddItemW/UpdateItemW repair. Existing AddItemW/UpdateItemW hook targets alone do not describe all replacement calls.
- Change: reuse the existing narrow AddItem evidence to recover GetMenu and four-argument Menu AddMenuItem; recover wide Menu UpdateMenuItem and Panel InvalidateLayout from the selected wide UpdateItem's valid-ID arm. Require current dropdown receiver, original ID/text/userData, constructed SetText message identity and deferred (false,false) layout on the combo receiver. Windows cleanup is derived from current callees; Linux alloca may obscure message text but not message identity. No copied addresses, fixed slot numbers or new pattern scan.
- Outputs: four vfuncs plus current Menu vtable for each of the existing 17 CS/CZ client platform nodes; 85 new artifacts. Keep the original finder and config platform boundaries.
- Verification: all 17 bounded analyzer nodes passed; 1511 unit tests (12 skips), 15 repository-contract tests passed. Current vtable targets/4-byte offsets and temporary input copy SHA-256 verified. 32 available same-build GameUI/client GetMenu and AddMenuItem slot comparisons matched; slots may match across modules but addresses belong to their own binaries.
- Consumer: VGUI2Extension installs the two client hooks after Client_FillAddress game identification. Windows czero 10210 live dropdown/selection check passed; the separate CBottomBar::SetPlayerText truncation remains outside those hooks. Canonical candidates and local pruned 21-snapshot catalog validated, but new records are not yet published online.

## Spectator selected caption follow-up (2026-10-16)

- Trigger: after repairing ComboBox AddItemW/UpdateItemW, the dropdown is complete but the selected caption is truncated again during spectator refresh.
- Root cause: CBottomBar::SetPlayerText independently allocates wcslen(text)+1 bytes before ConvertUnicodeToANSI (UTF-8). Confirmed czeror-10210 Windows 0x10033ab0, Linux 0x8a580; HLND2T_official/vgui2/game_controls/SpectatorGUI.cpp:457.
- Locator: intersect current #Spec_Map/#Spectators owners, inspect direct callees, prove original wide input -> local converted buffer -> player-list member virtual SetText. Derive member displacement from its actual load and SetText slot from the current ComboBox table. Older CS moves player formatting out of Update, so #Spec_PlayerItem_Team is not a valid universal owner anchor.
- Outputs: CBottomBar_SetPlayerText, CBottomBar_m_pPlayerList, vgui2_TextEntry_SetTextA. All 17 Windows/Linux CS/CZ nodes passed; 51 additional artifacts, no inherited address or fixed slot assumptions.
- Verification: upstream unit suite 1511 tests (12 skipped), repository-contract 15 tests, format check; all passed. Plugin uses exact UTF-8 sizing/checks and original narrow SetText dispatch. czero 10210 live verification preserved full Chinese name plus (100) after switching from Calvin to Irving; native view switched successfully.
