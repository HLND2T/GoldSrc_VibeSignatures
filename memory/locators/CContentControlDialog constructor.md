---
title: CContentControlDialog constructor
type: note
permalink: goldsrc-vibesignatures/locators/ccontent-control-dialog-constructor
tags:
- gameui
- anchors
- abi
- issue-323
---

# CContentControlDialog constructor

## Trigger

Adding the private GameUI content-control constructor requested in issue #323. The approved anchor is the password-reentry localization token.

## Root cause and constraints

- MetaHook/decompiler signatures expose an explicit ABI `this` parameter. The actual ELF identity is `CContentControlDialog::CContentControlDialog(vgui2::Panel*)`; C1/C2 constructor aliases share an entry.
- Sven 8948/10257 Windows omit the content-control dialog. Raw ASCII/UTF-16 scans and current-IDB mapped-data scans find no password-reentry token, class RTTI, resource, ContentControl command, or COptionsSubAdvanced class/resource. Current options-dialog construction was inspected. This is a platform-specific source/build difference; matching a Linux address or another Windows constructor would invent coverage.
- Sven 10257 Linux retains RTTI but lacks the private constructor symbol name. The recovered body creates the reentry Label and installs the CContentControlDialog primary table. Raw ELF RTTI verifies offset-to-top zero and the class name `21CContentControlDialog`.
- Default short entry signatures collide for several HL constructors. The existing expanded signature window provides unique output signatures. Compiler inlining of base/reset methods and MSVC/GCC object-layout differences do not change the target-owned string locator.

## Correct approach

`ida_preprocessor_scripts/find-CContentControlDialog_ctor.py` uses Pattern A with `FULLMATCH:#GameUI_PasswordReentryPrompt`, `prepare_c_strings`, and `preprocess_common_skill(old_yaml_map=None)`. Require one current string owner and a unique generated signature. Emit `CContentControlDialog_ctor.{platform}.yaml` with the ELF-verified demangled `func_name`, VA/RVA/size/signature. No prior artifact signature, LLM predecessor, code-pattern anchor, instruction ordinal, fixed window or vtable slot is used for discovery.

## Scope

Module `gameui`, category `func`: Windows HL3248/3266/3329/3647/4554/6153/8684/10210 and CoF5936 (9 inputs); Linux HL8684/10210 and Sven8948/10257 (4 inputs). Register the skill and symbol as Linux-only in both Sven configs. CS/CZ/CZDS configs have no independent GameUI module; older HL and CoF have no configured Linux input. All 13 applicable inputs retain a callable constructor body.

## Verification

2026-10-02: owned strict restored/no-save `-allgamever -modules gameui -skill find-CContentControlDialog_ctor -platform windows,linux` analysis succeeded for all 13 selected tasks, with zero failed/skipped tasks and Agent fallback unavailable. The 13 emitted artifacts match independent pre-implementation probes for VA, RVA and size. Each probe found one exact string, one code xref and one owning function with a caller; signatures were unique in the current image. Input SHA-256, x86 architecture and server health were verified. All 13 analysis endpoints were released, all owned workers ended and no task IDB lock remained. Per repository policy `idb_save` was not called.

| Tag | Platform | RVA | SHA-256 |
| --- | --- | --- | --- |
| cof-5936 | windows | 0x484e0 | 8255926f84eaa08e9096f2f78dea7f2827c3733e7af8f4408efa0b423acca838 |
| hl-10210 | linux | 0x9b600 | 6473a660d1f10c0de35c80fd328110266bb5eeb5d1d7eb07697a4867eda2ce0a |
| hl-10210 | windows | 0x1d3d0 | b9b8c0c36bd19681627001c06ce2a15496da06b72315d561a12a3964e0265811 |
| hl-3248 | windows | 0x33270 | 2f1424c3e9a471c5b92d42aaaad6e63227fd6af5967915482c48c75028a8ced9 |
| hl-3266 | windows | 0x332a0 | 384449b55753370586619b6908d178b4151bbef86eda0833310dea6aa1384c6a |
| hl-3329 | windows | 0x332a0 | 384449b55753370586619b6908d178b4151bbef86eda0833310dea6aa1384c6a |
| hl-3647 | windows | 0x32440 | b3588b7ca8f25c70cb062dc12f680e2e8abd75d271026d6e219055fe03a7b172 |
| hl-4554 | windows | 0x335e0 | 5359ffc4589711c625f88ba717391a05cfa91ce273e580a26e27298ad91f38ec |
| hl-6153 | windows | 0x32350 | 0c43c0c20f33c5d79fe48e3fa0fefcf37f626ce5a74581a1048171dbf000c10b |
| hl-8684 | linux | 0xe28d0 | fa1ff86540bd216d4d280bf18c02d8835fb7bfad5e58c8f17028bbb40b97cd74 |
| hl-8684 | windows | 0x324a0 | 684fb5615f0c3ab7d07fcf5503eb214d064c70e25eb0eb22bbf043b4d73c162f |
| svencoop-10257 | linux | 0x48af0 | 7bd0deabeb1ff8537c144043d0ba591587fb3e3090d14c6b18ffe14b511e3c39 |
| svencoop-8948 | linux | 0x608a0 | b0eb4ecdc1d79853ba159346b824fc9b7665e8aae75cb5d51330084be273b6e3 |

These addresses/hashes record the validated inputs only; they are not discovery constants. Independent `nm -C` checks confirmed constructor identities and entries on HL8684/HL10210/Sven8948 ELF. Both absent Windows inputs were separately checked through owned lifecycles.

## Source references and delivery

- `HLND2T_official/gameui/ContentControlDialog.cpp:31,43,60`: base construction, target-owned Label token and resource load.
- `HLND2T_official/gameui/OptionsSubAdvanced.cpp:92`: constructor caller in the reference source; current Sven Windows diverges.
- Existing helpers and generic repository-contract gates are reused; no shared runtime behavior, schema, dependency or production-specific contract test was changed.
- Related: [[idalib-mcp]], [[GameUI base panel and taskbar private symbols]].

## Delivery gates

2026-10-02: `uv run python tests/run_test_suite.py all -b --durations 30` ran 1381 tests, OK with 13 skips (platform/opt-in checks, unavailable live Redis groups and opt-in IDA environment test). The separate real 13-binary analysis above is the IDA evidence. `uv run python format_repo_files.py --check` and `git diff --cached --check` passed. The final source/config/artifact diff was reviewed; all 13 artifacts retain the category-specific identity and unique signatures, and every source binary hash is unchanged.
