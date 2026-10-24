---
title: CCDAudio MP3 stream and native volume locators
type: note
permalink: goldsrc-vibesignatures/ccdaudio-mp3-stream-and-native-volume-locators
tags:
- engine
- audio
- abi
- finder
- issue-403
---

# CCDAudio MP3 stream and native volume locators

## Overview

Issue [#403](https://github.com/HLND2T/GoldSrc_VibeSignatures/issues/403) supplies engine function records for a downstream Career music fade repair. The user confirmed the string/Miles-call anchors and explicitly requested a separate legacy integer setter. This repository changes symbol delivery only; it does not hook or modify playback.

## Responsibilities and identities

- `ida_preprocessor_scripts/find-CCDAudio-MP3.py` produces `CCDAudio__MP3_InitStream` and exactly one native setter identity.
- `CCDAudio__MP3_InitStream`: `bool CCDAudio::MP3_InitStream(int trackNum, bool looping)`.
- `CCDAudio__MP3_SetVolume`: `float CCDAudio::MP3_SetVolume(float newVolume)`, normalized [0,1].
- `CCDAudio__MP3_SetVolume_int`: legacy `int CCDAudio::MP3_SetVolume(int newVolume)`, clamp [0,127]; returns -1 when unchanged and the effective integer after a change. This source-style overload name is a semantic reconstruction from Windows machine code, not a recovered old Linux symbol.
- All are module `engine`, category `func`; no object/field/global-variable records are requested.
- Canonical Linux names recovered from raw ELF bytes: `_ZN8CCDAudio14MP3_InitStreamEib`, `_ZN8CCDAudio13MP3_SetVolumeEf`. Filename overload is `_ZN8CCDAudio14MP3_InitStreamEPKcb` and is not the requested entry.
- Config aliases retain the canonical and source-style spellings. Artifact stems and func_name use the repository logical names above.

## Anchors and acceptance

InitStream first uses its own exact success diagnostic, or the HL25 Windows wide-string assertion `1 < trackNum && trackNum < g_iMP3NumTracks`. Each present literal and its owner must be unique. HL10210 Linux has none of these literals; its AIL_open_stream reference has exactly one owner. Verify the playback-rate / stream-userdata / cached-volume API chain and no start call in the body. The initializer and setter must reference the same current stream storage.

The setter has no target-owned string; Linux optimizes its callers by inlining, leaving an independently callable setter with zero direct callers. Seed owners through imported Miles volume API xrefs, resolving IAT/PLT thunks. Require the standalone body's only semantic calls to be AIL_stream_sample_handle + AIL_set_sample_volume_pan, or legacy AIL_set_stream_volume. Reject Init, Frame, CDUpdate and import thunks. Verify clamp constants, one native-this read/write cache, return shape and shared stream storage. Fail closed on absence or ambiguity. No reference RVA, member offset, call ordinal, old YAML signature or discovery byte pattern participates.

## ABI and version differences

Windows x86: native thiscall, this in ECX. Init has two 4-byte argument slots (bool consumed as low byte), returns AL, ret 8. Each setter has one 4-byte parameter slot, ret 4. Float setters return via x87 ST0, integer setters via EAX. Linux x86: this and arguments in cdecl stack slots, plain ret; bool in AL, float via ST0.

HL SO recovered types plus reference source declare float. Sven IDA may guess double/long double: ST0 and non-template Itanium names alone do not prove a C++ return declaration. The float declaration for stripped Sven is inferred from the corresponding source semantics and matched f32 argument/cache operations; do not present decompiler guesses as source truth.

Cache displacements are observations, never finder rules: HL +0x5dc, Sven DLL +0x28, Sven SO +0x24. Sven also moves track map/count into the object and changes path lookup / range validation. All inspected implementations still use Miles.

## Callers and ordering

Reference source `D:/BarsTech_goldsrc_compatible_public-main/engine/cd.cpp`: Prime :392, integer Play :999, filename Play :1014, Finalize :1025, SetVolume :1113, integer Init :1131, filename Init :1166, Start :1175.

- Filename Init checks null/empty, resolves a track index, then calls or tail-jumps to integer Init.
- Prime's integer/filename branches reach integer Init and set primed, without starting.
- Play initializes unless already primed, then reaches Finalize/its inlined body and AIL_start_stream.
- Integer Init opens/configures the stream and optional looping but does not start it; a successful-return hook can correct effective volume before start.
- Sven Windows filename Init and Start may be absent from IDA's function list while their callable code remains present; their linear disassembly and call targets were checked without adding functions.
- No unrelated overload, Prime/Play wrapper, requested/base volume method, sound-effect setter or inline owner is substituted.

## Coverage matrix

Values below are independently checked RVAs, evidence only. Windows imagebase is 0x1d00000 except HL10210 at 0x10000000; ELF base is zero. BLOB tags analyze the existing hw.decrypt.dll rebuilt from hw.dll; in-memory decrypt output was byte-identical for all four.

| Input | InitStream RVA | Native setter RVA | Setter |
| --- | --- | --- | --- |
| hl-3248 Windows BLOB | 0xd010 | 0xcfc0 | int |
| hl-3266 Windows BLOB | 0xd010 | 0xcfc0 | int |
| hl-3329 Windows BLOB | 0xd020 | 0xcfd0 | int |
| hl-3647 Windows BLOB | 0xd010 | 0xcfc0 | int |
| hl-4554 Windows | 0x17730 | 0x176e0 | int |
| cof-5936 Windows | 0x216ec | 0x2167c | int |
| hl-6153 Windows | 0xa5c0 | 0xa530 | float |
| hl-8684 Windows | 0xa640 | 0xa5b0 | float |
| hl-8684 Linux | 0x1fe980 | 0x1fe8d0 | float |
| hl-10210 Windows | 0x1943a0 | 0x1946b0 | float |
| hl-10210 Linux | 0x1aeb30 | 0x1aea90 | float |
| svencoop-8948 Windows | 0x18e70 | 0x18df0 | float |
| svencoop-8948 Linux | 0x1c7a80 | 0x1c79d0 | float |
| svencoop-10257 Windows | 0x18d40 | 0x18cb0 | float |
| svencoop-10257 Linux | 0x17bb70 | 0x17bac0 | float |
| cstrikegameui-8684 Windows | 0xa640 | 0xa5b0 | float, identical HL8684 input |

12 engine configs, 16 declared platform inputs, 32 function records. Float records are genuinely absent for the six legacy backends; int records are absent for float backends. No extra platform is invented for Windows-only configs. Other game configs (cstrike/czero/czeror/bshift/gearbox/decay) do not declare an engine module here.

## Binary identity

SHA256 of the actual IDA input (BLOB rows refer to reconstructed PE, not the source BLOB hash). Formal snapshots bind the source binary identity through the normal writer, including is_blob.

| Input | SHA256 |
| --- | --- |
| hl-3248 Windows | 7311ec923c5644a4c81fb1c887d1062f7732c3b7152ad0469ff367bc0094feb0 |
| hl-3266 Windows | d00aed229438f2b3dbe0c77f37657b903e6c35893ee1d39e4695afbfffefee21 |
| hl-3329 Windows | 4b42b89992cda6ef5b84c1bb56556f5b15b1e0c2a3a7b9f04fe053dcf24c4480 |
| hl-3647 Windows | 7d4bee5d199c40d738c0bc2ed668c0fd8830278e2fed1f320b07832fda993110 |
| hl-4554 Windows | 482871315f4a713a8aa72c5e2a73092d261bacb618890a4523630e9e168eb2a3 |
| hl-6153 Windows | 5d9958f8111197f5fb22cc2a44f05239f4d5c9a48b8795f2bc287d507258a257 |
| cof-5936 Windows | 9dd34e536c4bb7cda3bc1bc4f0f5f6163687566a16f35c0ea0be59f93da62875 |
| hl-10210 Windows | 9ba9a2db5e07598fd59afa35507a98c86162e4e15b3835177b78c11842cd2295 |
| hl-10210 Linux | fca6628b5a4d76a945e11b9796f327004edc65420d9f9cc23f883143508edd78 |
| hl-8684 Windows / cstrikegameui-8684 Windows | be45f76049a133392423679d334c69c8e1e7e82dc873eebdd229ea0341ba1b10 |
| hl-8684 Linux | 1e775773292407106ac17c98bc19f0444e8f1525d46e592de5cc53afad2b89e1 |
| svencoop-8948 Windows | 22fd4d1ad0d3e11a44e7cd5643fe9f6b8ded1234cce819cc242ba5a3fd338ce8 |
| svencoop-8948 Linux | aad1299bf2389070f9fa27a7413543e028f8b26ef50d7ecfaa11504be26e4b0e |
| svencoop-10257 Windows | e3c7f374b70845fb6f45c05906e4b5fe3dc9f394ab37bb653501d3b6a3282596 |
| svencoop-10257 Linux | 8cead76a51204a4ba1036c85cc2099b7c3542950d924846a9aa2ccf619df7dfd |

## Root cause and reusable constraints

Trigger: EOF during a Career music fade leaves effective volume attenuated; a subsequent stream uses that stale cache while requested volume is unchanged. Downstream can restore effective volume after successful shared Init, before playback. This repository provides the entry and setter, not that behavior change.

Correct handling: separate legacy int and float identities; check current-machine semantics and ABI; don't infer absence from IDA function boundaries or a missing direct caller. IDA x87 memory operands use dt_float, while SSE scalar operands may be dt_dword; use instruction width. Filter PIC arithmetic references (_DYNAMIC on Sven) out of actual stream-load/store evidence.

Verification: run the production finder from fresh outputs on every configured engine platform, require unique emitted signatures and exact surveyed RVAs, reject opposite-ABI output requests, then verify snapshot/metadata/catalog contracts and repository checks. Runtime gameplay repair remains outside this issue's implementation scope.

## Evidence lifecycle

Read-only exploration used shared-supervisor idb_list then exact idb_open, verified file/IDB hashes and x86, and finalized every owned session with idb_close(save=True), saved=true. No external session was closed. The production analyzer uses strict warm consumer sessions with no save; no binary or bin-submodule files are staged.

## Delivery validation (2026-10-24)

- Production `ida_analyze_bin.py -allgamever -modules engine -skill find-CCDAudio-MP3 -platform windows,linux` completed with 16 successes, 0 failures and 0 skipped inputs. All 32 fresh output files matched the tracked artifacts byte for byte.
- The complete repository suite ran 1,575 tests: OK with 16 environment/opt-in skips. Actual IDA coverage was verified separately by the production command above.
- All 12 snapshot candidates passed metadata verification, guarded JSON catalog and gamedata generation, companion marking and local candidate publication. Reopened records retained engine/function identity, aliases, exact snapshot payloads and binary SHA256; the content-addressed catalog index contains all 32 MP3 records.
- Repository format checks, targeted Ruff (excluding N999 for the required hyphenated finder filename), whitespace checks and an independent finder/ABI/coverage review passed.
- These local candidate checks do not constitute a formal release. The immutable release workflow must publish the merged source and its manifest before downstream delivery is complete.

## Stripped PIC thunk names (PR validation)

- Trigger: initial remote PR analysis rejected Sven 10257 Linux's standalone setter, although all local warm-IDB inputs passed.
- Root cause: the surveyed local IDB named the PIC helper `get_pc_thunk`, while a pristine IDB and CI named it `sub_*`. The extra-call exclusion depended on that name.
- Correct handling: recognize the helper's decoded return-address load from `[esp]`, plain return and caller's immediately following addition to the same GOT-base register. Keep the Miles API/cache/clamp/stream checks unchanged; do not rename a callee or depend on saved exploratory names.
- Verification: reproduced the rejection from a new temporary copy of the original Sven 10257 ELF with default auto-analysis; the corrected walk recovered Init `0x17bb70` and float setter `0x17bac0` with the unnamed helper. Closed the owned session with save=true/saved=true.
- Scope: this finder’s stripped Linux PIC setup; downstream runtime behavior is unchanged.

The corrected finder was rerun across all 16 configured engine inputs; all 32 regenerated artifacts remain byte-identical. Local candidate catalog verification also checks that every index URL resolves to the exact guarded dataset bytes (build the index from original encoded datasets, since reloading JSON changes numeric vtable-key sorting). The existing downstream manifest pruner and production MetaHook GameData Query/Resolve passed for all 24 Windows MP3 records using original-file CRC64, including BLOB identities and opposite-ABI absence. A temporary x86 harness registered inert image ranges and did not execute engine functions; formal release consumption is verified separately.
