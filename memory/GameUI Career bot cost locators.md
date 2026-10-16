---
title: GameUI Career bot cost locators
type: note
permalink: goldsrc-vibesignatures/game-ui-career-bot-cost-locators
tags:
- gameui
- career
- locator
- vgui2
---

# GameUI Career bot cost locators

## Overview
Issue #377 adds GameUI artifacts needed to call the original Career bot character setter, obtain the full integer cost, and replace its cost TextImage with complete localized text. It does not implement the downstream MetaHookSv plugin or establish runtime layout behavior.

## Responsibilities
- `CBotButton_SetCharacter` (func): canonical `CBotButton::SetCharacter(CCareerCharacter const*)`, complete entry including nonempty character behavior.
- `CCareerCharacter_GetPoints` (func): canonical `CCareerCharacter::GetPoints() const`, unmodified full-width integer return.
- `CBotButton_m_pText` (structmember): array base relative to CBotButton, with an instruction-validated member offset; not a global or an independently addressed array element. Array extent is deliberately not invented.
- `vgui2_TextImage_SetTextW` (vfunc): canonical `vgui2::TextImage::SetText(wchar_t const*)`, with callable function VA/RVA/signature plus current vtable index/offset.
- `vgui2_TextImage_vtable` (vtable): canonical `vgui2::TextImage` primary RTTI table.

## Involved Files & Symbols
- `ida_preprocessor_scripts/find-GameUI-career-bot-cost.py`
- `ida_preprocessor_scripts/find-vgui2_TextImage-SetText.py`
- `ida_preprocessor_scripts/_career_bot_cost_common.py`
- `ida_preprocessor_scripts/_x86_vcall_flow.py`: bounded CMOV alternatives; unknown source or destination still destroys certainty.
- `tests/test_x86_vcall_flow.py`: synthetic conditional-move provenance regression.
- `configs/hl-*.yaml`, `configs/cof-5936.yaml`: Career and generic TextImage registrations.
- `configs/svencoop-8948.yaml`, `configs/svencoop-10257.yaml`: generic TextImage only.
- `bin_artifacts/<tag>/gameui/`: category-correct generated YAML.
- Reference source: `D:/BarsTech_goldsrc_compatible_public-main/GameUI/CareerGame.cpp:32`; interface comparison: `D:/MetaHookSv/MetaHook/include/vgui_controls/TextImage.h:41`. Target binaries remain authoritative.

## Architecture
The user confirmed all four anchor proposals in the #377 implementation conversation before production implementation.

Career: exact NUL-terminated `#Career_Cost` raw-data xrefs -> unique complete SetCharacter owner; corroborate `BotPointsFont`, `BotNameFont`, and the `EmptyChar` branch. Hex-Rays CTree identifies the direct call participating in `GetPoints() % 10 + '0'`; decoded machine CALL and the stored character parameter independently validate its receiver. Decode the matching wide TextImage call between cost localization and points-font setup, recover its this-relative member array base, and independently decode a LEA/load operand yielding that offset.

TextImage: current primary RTTI -> unique method that checks its char input for '#' and converts it to a local Unicode buffer -> same-object virtual dispatch consuming that buffer -> current wide slot. Confirm wide loads or CRT length/copy operations with argument provenance, current stack cleanup, and exact Itanium identity when present. This works without Career and therefore covers Sven too.

GCC's guarded devirtualization can merge the converted buffer and a localization result at the wide call. Both actual paths are retained. The generic tracer now preserves CMOV alternatives instead of silently losing the text pointer. No discovery uses old YAML signatures, version switches, reference RVAs, SDK declaration order, or fixed member/slot constants. Output signatures are generated after discovery; short getters may require the existing across-function-boundary output directive. No LLM fallback or generated reference YAML is needed.

## Dependencies
- [[idalib-mcp]], current-binary RTTI and x86 flow helpers, unique function/member signature validators.
- Hex-Rays for the semantic modulo-ten call expression.
- Career finder declares `vgui2_TextImage_SetTextW.<platform>.yaml` as a required DAG input.
- Existing localize interfaces remain usable by the downstream consumer; no new ILocalize artifact or interface contract is introduced.

## Notes
### Coverage and ABI
All values below are observed evidence for the exact SHA-256 inputs, never discovery constants. Module is `gameui` in every row. Windows is PE32/I386 with image base 0x10000000; Linux is ELF32/I386 with image base zero. Vtable pointers/slots are four bytes.

Windows member calls use ECX for this. GetPoints has no explicit argument and zero stack purge; wide SetText consumes one pointer argument (`retn 4`). Linux member calls use cdecl with explicit this, and native 32-bit wchar_t. Windows wchar_t is 16-bit. The local MetaHook header adds a bool to wide SetText, while these target overloads have only the wide pointer: do not dispatch through that incompatible declaration. IDA's short demangler drops GetPoints' const qualifier, so the finder checks `_ZNK16CCareerCharacter9GetPointsEv` directly.

Career is verified for eight HL tags (3248, 3266, 3329, 3647, 4554, 6153, 8684, 10210) and COF-5936 on Windows; HL-8684 and HL-10210 additionally on Linux. Other platforms are not declared by those configs. Both Sven tags lack the Career literals/classes and carry no Career registration; their TextImage support is verified separately. CS/CZ/CZEROR configs declare client modules; consumers use the shared HL GameUI results instead of putting these symbols in client.

In HL-10210 Linux, 0x5AF20 is the empty-character constprop specialization; only the full 0x5C270 entry owns #Career_Cost. COF keeps BotProfile::GetCost out of line: expand only a proven side-effect-free leaf getter with its actual receiver. IDA/FLIRT labels that identical tiny callee as a Concurrency library method, which must not determine semantic identity.

| Snapshot | Platform | SetCharacter VA | GetPoints VA | m_pText offset | SetTextW VA | Slot |
|---|---|---|---|---|---|---|
| cof-5936 | windows | 0x10004283 | 0x1000f929 | 0x1c8 | 0x1006588e | 26 |
| hl-10210 | linux | 0x5c270 | 0x63a50 | 0x1c8 | 0x127490 | 29 |
| hl-10210 | windows | 0x1000df30 | 0x10013f60 | 0x1cc | 0x1005a6d0 | 27 |
| hl-3248 | windows | 0x10003290 | 0x10009dd0 | 0x1c8 | 0x10049190 | 26 |
| hl-3266 | windows | 0x10003290 | 0x10009dd0 | 0x1c8 | 0x10052df0 | 26 |
| hl-3329 | windows | 0x10003290 | 0x10009dd0 | 0x1c8 | 0x10052df0 | 26 |
| hl-3647 | windows | 0x100032d0 | 0x10009d90 | 0x1c8 | 0x10048690 | 26 |
| hl-4554 | windows | 0x100032d0 | 0x1000a2d0 | 0x1c8 | 0x10049c70 | 26 |
| hl-6153 | windows | 0x100032d0 | 0x10009d90 | 0x1c8 | 0x10049200 | 26 |
| hl-8684 | linux | 0xaabb0 | 0xb1be0 | 0x1c4 | 0x153460 | 28 |
| hl-8684 | windows | 0x100032d0 | 0x10009d90 | 0x1c8 | 0x10049350 | 26 |
| svencoop-10257 | linux | absent | absent | absent | 0xe21a0 | 28 |
| svencoop-10257 | windows | absent | absent | absent | 0x1004b870 | 26 |
| svencoop-8948 | linux | absent | absent | absent | 0xf9f50 | 28 |
| svencoop-8948 | windows | absent | absent | absent | 0x1004b1a0 | 26 |

| Snapshot / Platform | SHA-256 |
|---|---|
| cof-5936 / windows | `8255926f84eaa08e9096f2f78dea7f2827c3733e7af8f4408efa0b423acca838` |
| hl-10210 / linux | `6473a660d1f10c0de35c80fd328110266bb5eeb5d1d7eb07697a4867eda2ce0a` |
| hl-10210 / windows | `b9b8c0c36bd19681627001c06ce2a15496da06b72315d561a12a3964e0265811` |
| hl-3248 / windows | `2f1424c3e9a471c5b92d42aaaad6e63227fd6af5967915482c48c75028a8ced9` |
| hl-3266 / windows | `384449b55753370586619b6908d178b4151bbef86eda0833310dea6aa1384c6a` |
| hl-3329 / windows | `384449b55753370586619b6908d178b4151bbef86eda0833310dea6aa1384c6a` |
| hl-3647 / windows | `b3588b7ca8f25c70cb062dc12f680e2e8abd75d271026d6e219055fe03a7b172` |
| hl-4554 / windows | `5359ffc4589711c625f88ba717391a05cfa91ce273e580a26e27298ad91f38ec` |
| hl-6153 / windows | `0c43c0c20f33c5d79fe48e3fa0fefcf37f626ce5a74581a1048171dbf000c10b` |
| hl-8684 / linux | `fa1ff86540bd216d4d280bf18c02d8835fb7bfad5e58c8f17028bbb40b97cd74` |
| hl-8684 / windows | `684fb5615f0c3ab7d07fcf5503eb214d064c70e25eb0eb22bbf043b4d73c162f` |
| svencoop-10257 / linux | `7bd0deabeb1ff8537c144043d0ba591587fb3e3090d14c6b18ffe14b511e3c39` |
| svencoop-10257 / windows | `99382b87319d21139c0675d8a45669d64ef930f9e43dbd582461575383545f75` |
| svencoop-8948 / linux | `b0eb4ecdc1d79853ba159346b824fc9b7665e8aae75cb5d51330084be273b6e3` |
| svencoop-8948 / windows | `0f653d41010add218b1baeea57ffaeb9875eba1cc78157bc0cf17d300a90a524` |


### Verification environment and reproducibility
The shared 127.0.0.1:13337 endpoint was unreachable, so acquisition used the documented owned-lifecycle fallback. Many original Windows/older IDBs were rejected by the repository's .id0 lock check. Original lock files and processes were left untouched. Exact binary copies were analyzed in `%TEMP%/gsvibe-377-bins/<tag>/gameui/`; every copy's SHA-256 was compared with its configured original. Fresh IDBs were built against their own copied inputs, rather than copying an IDB with stale input-path identity.

The preparation lifecycle saved each owned IDB normally and released its worker. Final analyzer runs used restored_strict/no-save. The independently opened original HL-10210 Linux IDB was saved and closed by its owned lifecycle; its recorded final modification time was 2026-10-15 16:18:31 UTC. The original IDB path is `D:/GoldSrc_VibeSignatures/bin/hl-10210/gameui/gameui.so.i64`.

A selection derived from all production configs included every applicable new node: 11 tags, 15 binaries, 26 nodes. From an empty artifact root, `ida_analyze_bin.py -batch_selection %TEMP%/gsvibe-377-selection.json -bindir %TEMP%/gsvibe-377-bins -artifactdir %TEMP%/gsvibe-377-verified3 -batch_diagnostics %TEMP%/gsvibe-377-final-diagnostics3 -debug` exited zero and emitted exactly 63 task artifacts. Current diagnostic generation: `analysis-batch-20261016T005835-6a7a903aa35b404ab8a91b7cd10b4131`.

Existing `find-GameUI-ComboBox` was rebuilt on all 15 GameUI binaries in a separate artifact root seeded only with its declared inputs. All 15 nodes succeeded; all 180 resulting YAML payloads equal the repository's prior payloads. Formatting check and git diff --check passed. `python tests/run_test_suite.py all -b --durations 30` finished with 1528 tests, OK (16 environment/opt-in skips), in 245.576 seconds. This includes unit, Redis integration and repository-contract suites. Real IDA integration is opt-in and skipped by that suite; the separate 15-binary rebuild and 15-binary ComboBox regression provide the actual IDA evidence.

### Reusable lessons
- Trigger: Unicode discovery loses its input after null-to-empty fallback. Constraint: CMOV preserves either the input pointer or the empty literal, while unknown-write handling erased both. Correct approach: retain bounded alternatives, fail closed for unknown alternatives, and bind the conversion output to the actual same-object wide dispatch. Verify with synthetic CMOV known/unknown inputs and all configured binary families.
- Trigger: a short cost getter appears to return an unrelated library object. Constraint: identical leaf bytes can receive a misleading FLIRT identity, and unoptimized builds retain an extra accessor call. Correct approach: use the confirmed Career caller, validate the receiver, and expand only a side-effect-free leaf; require unmodified full-width profile scalar or guarded zero. Verify on COF as well as optimized HL.
- Trigger: a wide CRT call has no local callee, or Windows ECX appears unrelated. Constraint: external PLT calls need not resolve locally, and Windows CRT functions are cdecl. Correct approach: use loader import identity plus Linux outgoing args / Windows stack args, respecting the CRT argument position. Verify both Sven Linux and COF Windows.

## Callers
- The confirmed SetCharacter body calls GetPoints and the wide TextImage slot to build and display the localized Career cost.
- The analyzer runs the two registered finders through their declared DAG; downstream MetaHookSv hook implementation and runtime layout testing are outside #377.
