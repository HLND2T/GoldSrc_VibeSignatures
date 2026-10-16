---
title: GameUI Career player name locators
type: note
permalink: goldsrc-vibesignatures/game-ui-career-player-name-locators
tags:
- gameui
- career
- locator
- vgui2
- unicode
---

# GameUI Career player name locators

## Overview
Issue #379 provides GameUI symbols for downstream Unicode correction of Career TextLabel and PlayerNameLabel. It supplies complete hook entries, two pointer-member operands and the wide Label overload; plugin changes and runtime UI verification remain downstream work.

## Responsibilities
- `CCareerDifficultyBox_ctor` (func): `CCareerDifficultyBox::CCareerDifficultyBox(char const*, vgui2::Panel*)`, complete entry.
- `CCareerBaseFrame_Activate` (func): `CCareerBaseFrame::Activate()`.
- `CCareerBaseBox_m_pTextLabel` (structmember): canonical `CCareerBaseBox::m_pTextLabel`, four-byte Label pointer.
- `CCareerBaseFrame_m_pPlayerName` (structmember): four-byte Label pointer.
- `vgui2_Label_SetTextW` (vfunc): `vgui2::Label::SetText(wchar_t const*)`, callable function and current Label slot. Distinct from both char* and TextImage overloads.

## Involved Files & Symbols
- `ida_preprocessor_scripts/find-GameUI-career-player-name.py`
- `ida_preprocessor_scripts/find-vgui2_Label-SetText.py`
- `ida_preprocessor_scripts/_career_player_name_common.py`
- `configs/hl-*.yaml`, `configs/cof-5936.yaml`: Career and generic Label registrations.
- `configs/svencoop-8948.yaml`, `configs/svencoop-10257.yaml`: generic Label only.
- `bin_artifacts/<tag>/gameui/`: 59 generated artifacts.
- Reference declaration: `D:/BarsTech_goldsrc_compatible_public-main/GameUI/CareerBox.h:14,54,77,82`; target binaries are authoritative.

## Architecture
All three anchor groups were explicitly approved by the user before implementation.

1. Exact resource/CareerBoxDifficulty.res, Difficulty0Button/1Button and #Career_Difficulty%d owners intersect at the full difficulty constructor. Current primary RTTI assignment, the base-constructor call and original argument provenance establish complete-object identity and parameter order.
2. CareerBoxScheme plus TextLabel anchor the base constructor; the newly created Label pointer store yields m_pTextLabel. The difficulty name-cvar -> wide formatter -> Label call must use that member. Older builds retain a small SetLabelText wrapper: accept only a verified single forwarding call with unchanged receiver/text and no object stores. Keep the hook on the complete constructor.
3. PlayerNameLabel plus MissionPackNameLabel and CareerScheme anchor BaseFrame construction. Cross-check the player-member creation store with the wide-buffer call in the unique #Cstrike_Bot_Difficulty%d Activate owner and its current primary vtable entry.
4. Independently obtain current Label RTTI, identify forwarding of the original wide input to a child using the verified TextImage wide dispatch, and verify the same input's Label hotkey call. Recover the Label slot from its own table, never from adjacent slots or SDK order.

Repeated literal storage is permitted only when exact owning-function intersection and receiver validation are unique; COF has two CareerBoxScheme copies. Signatures are output validation after discovery. No old signature, version switch, fixed RVA/member offset/slot, or LLM fallback participates.

## Dependencies
- [[GameUI Career bot cost locators]] and its verified `vgui2_TextImage_SetTextW` dependency.
- [[idalib-mcp]], current RTTI, shared x86 receiver/value flow, unique signature and struct-operand validators.
- Career finder declares the new wide Label artifact as its required DAG input. Existing name-cvar and localization interfaces are reused.

## Notes
### Coverage and ABI
Module is gameui throughout. All rows are measured results for the exact SHA-256 inputs below, not discovery constants. Windows inputs are PE32/I386 at image base 0x10000000; Linux inputs are ELF32/I386 at zero. Pointer width is four bytes.

| Snapshot | Platform | Difficulty ctor VA | Activate VA | BaseBox text offset | Frame player offset | Label SetTextW VA | Label slot |
|---|---|---|---|---|---|---|---|
| cof-5936 | windows | 0x1000a79d | 0x10002873 | 0x134 | 0x12c | 0x1005b4d0 | 134 |
| hl-10210 | windows | 0x1000f070 | 0x10009210 | 0x13c | 0x134 | 0x1004ef80 | 134 |
| hl-10210 | linux | 0x61590 | 0x59ab0 | 0x13c | 0x134 | 0xdc960 | 136 |
| hl-3248 | windows | 0x10006e30 | 0x10002290 | 0x130 | 0x128 | 0x10041260 | 134 |
| hl-3266 | windows | 0x10006e30 | 0x10002290 | 0x130 | 0x128 | 0x10043350 | 134 |
| hl-3329 | windows | 0x10006e30 | 0x10002290 | 0x130 | 0x128 | 0x10043350 | 134 |
| hl-3647 | windows | 0x10006e00 | 0x10002290 | 0x130 | 0x128 | 0x100405f0 | 134 |
| hl-4554 | windows | 0x10006fc0 | 0x10002290 | 0x134 | 0x12c | 0x10041760 | 134 |
| hl-6153 | windows | 0x10006e00 | 0x10002290 | 0x134 | 0x12c | 0x10041120 | 134 |
| hl-8684 | windows | 0x10006e00 | 0x10002290 | 0x134 | 0x12c | 0x10041270 | 134 |
| hl-8684 | linux | 0xb02e0 | 0xa5b60 | 0x134 | 0x12c | 0x1157c0 | 136 |
| svencoop-10257 | windows | absent | absent | absent | absent | 0x100271a0 | 134 |
| svencoop-10257 | linux | absent | absent | absent | absent | 0x8b480 | 136 |
| svencoop-8948 | windows | absent | absent | absent | absent | 0x10026ee0 | 134 |
| svencoop-8948 | linux | absent | absent | absent | absent | 0xa3230 | 136 |

All 11 Career inputs have independent complete entries; none requires an inlined-only status. Sven's four inputs lack the resource path, PlayerNameLabel, difficulty token and all three Career RTTI class names (zero raw binary occurrences for each). These four rows are explicitly absent for all four Career targets, with generic Label support present. Other platform/tag combinations are not declared GameUI inputs. CS/CZ/CZEROR consumers use shared HL GameUI, not client artifacts.

RTTI and base-constructor receiver flow show CCareerDifficultyBox's CCareerBaseBox subobject at adjustment zero on all 11 inputs. Publish the inherited member once under CCareerBaseBox; downstream can use that offset on the complete difficulty object for these verified inputs.

Windows constructors use ECX=this, stack arguments panelName then parent, `retn 8`, and return this in EAX. ELF uses cdecl with explicit this, then panelName and parent; constructors have void return semantics. Raw ELF symbol-table inspection confirms C1 and C2 are same-address aliases in both HL-8684 (0xb02e0) and HL-10210 (0x61590). The Activate canonical symbol is `_ZN16CCareerBaseFrame8ActivateEv`; wide Label is `_ZN5vgui25Label7SetTextEPKw`.

Wide Label takes one wide pointer (no extra bool), using Windows thiscall/`retn 4` and UTF-16 versus Linux cdecl and 32-bit wchar_t. Linux may end with a restored-stack tail dispatch. Windows EH cleanup funclets contain unrelated returns; validate primary-body stack cleanup rather than treating those funclets as callable constructor exits. Verify the register-preserving normal path of a tiny security-cookie helper before retaining EAX provenance.

| Snapshot / platform | SHA-256 |
|---|---|
| cof-5936 / windows | `8255926f84eaa08e9096f2f78dea7f2827c3733e7af8f4408efa0b423acca838` |
| hl-10210 / windows | `b9b8c0c36bd19681627001c06ce2a15496da06b72315d561a12a3964e0265811` |
| hl-10210 / linux | `6473a660d1f10c0de35c80fd328110266bb5eeb5d1d7eb07697a4867eda2ce0a` |
| hl-3248 / windows | `2f1424c3e9a471c5b92d42aaaad6e63227fd6af5967915482c48c75028a8ced9` |
| hl-3266 / windows | `384449b55753370586619b6908d178b4151bbef86eda0833310dea6aa1384c6a` |
| hl-3329 / windows | `384449b55753370586619b6908d178b4151bbef86eda0833310dea6aa1384c6a` |
| hl-3647 / windows | `b3588b7ca8f25c70cb062dc12f680e2e8abd75d271026d6e219055fe03a7b172` |
| hl-4554 / windows | `5359ffc4589711c625f88ba717391a05cfa91ce273e580a26e27298ad91f38ec` |
| hl-6153 / windows | `0c43c0c20f33c5d79fe48e3fa0fefcf37f626ce5a74581a1048171dbf000c10b` |
| hl-8684 / windows | `684fb5615f0c3ab7d07fcf5503eb214d064c70e25eb0eb22bbf043b4d73c162f` |
| hl-8684 / linux | `fa1ff86540bd216d4d280bf18c02d8835fb7bfad5e58c8f17028bbb40b97cd74` |
| svencoop-10257 / windows | `99382b87319d21139c0675d8a45669d64ef930f9e43dbd582461575383545f75` |
| svencoop-10257 / linux | `7bd0deabeb1ff8537c144043d0ba591587fb3e3090d14c6b18ffe14b511e3c39` |
| svencoop-8948 / windows | `0f653d41010add218b1baeea57ffaeb9875eba1cc78157bc0cf17d300a90a524` |
| svencoop-8948 / linux | `b0eb4ecdc1d79853ba159346b824fc9b7665e8aae75cb5d51330084be273b6e3` |

### Verification
All 15 temporary binary inputs were compared against the configured originals and have identical SHA-256. Real analyzer runs use restored_strict/no-save. All 26 new nodes succeeded with zero failures/skips (24 nodes across 14 inputs plus two COF nodes). Only the verified TextImage dependency was seeded; all 59 new task outputs were generated by the new finders.

- 14-input batch: `gsvibe379-diagnostics6/analysis-batch-20261016T121120-17327ba8067f416c8c3062bf79fc45d2`.
- COF batch: `gsvibe379-cof-diagnostics/analysis-batch-20261016T121307-35e0971833d840da8e0fcf38067a2af7`.
- Batch selections and logs are under the session TEMP directory, outside the repository. The 14-input run uses prior verified `gsvibe-377-bins` warm inputs. After an exploratory COF IDB left side files, a new exact binary copy in `gsvibe379-fresh/cof-5936/gameui/` was warmed independently; no stale lock was deleted.
- Initial exploration used shared-supervisor idb_open for HL-10210 Windows/Linux and the COF temporary input. Each task-opened session was finalized with idb_close(save=True), reporting success and saved=true. The unrelated externally managed gameui session was untouched.
- Existing TextImage, Career bot cost and ComboBox nodes were independently rebuilt: 41/41 nodes succeeded. Rebuilt/seeded regression YAML payloads match repository payloads.
- `uv run python tests/run_test_suite.py all -b --durations 30`: 1528 tests, OK (16 environment/opt-in skips), 201.913 seconds. The final run includes the staged artifacts required by the repository's tracked-inventory gate. Initial system-Python execution lacked botocore; the project uv environment supplies the existing dependency. No dependency declaration changed.
- `uv run python format_repo_files.py --check` and `git diff --cached --check` passed. All 243 expected regression outputs, excluding seeded inputs, match the original repository YAML payloads.
- Final saved original HL-10210 IDBs: `bin/hl-10210/gameui/GameUI.dll.i64` at 2026-10-16 04:05:20.407384 UTC; `bin/hl-10210/gameui/gameui.so.i64` at 2026-10-16 04:05:20.497464 UTC. Fresh COF warm IDB: `%TEMP%/gsvibe379-fresh/cof-5936/gameui/GameUI.dll.i64` at 2026-10-16 04:15:24.567808 UTC. Binary and IDA scratch files are not staged.

### Reusable lessons
- Trigger: an old constructor has no direct wide Label dispatch. Constraint: SetLabelText remains an out-of-line wrapper. Correct approach: verify the complete short forwarding body and original text argument; retain the complete constructor as hook target. Verify across COF and old HL inputs.
- Trigger: constructor return flow appears to lose this in EAX. Constraint: a security-cookie helper preserves registers on success, while separate EH funclets use different return cleanup. Correct approach: validate the helper's full returning path and the primary body ABI separately. Verify on HL-10210 Windows.
- Trigger: Linux wide Label appears to have more than one input-consuming self-call. Constraint: a restored-stack repaint tail exposes inherited incoming arguments. Correct approach: distinguish explicit hotkey calls from tail cleanup and validate actual wide forwarding. Verify on HL and stripped Sven ELF inputs.

## Callers
- The complete difficulty constructor formats name-cvar text and sets the inherited TextLabel.
- BaseFrame Activate rebuilds name/difficulty text and updates PlayerNameLabel, then updates MissionPackNameLabel.
- Downstream VGUI2Extension can call the original functions and overwrite the two labels with explicitly decoded Unicode text.
