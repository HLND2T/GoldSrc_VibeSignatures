---
title: Client sound viewport and colors
type: note
permalink: goldsrc-vibesignatures/locators/client-sound-viewport-and-colors
tags:
- locator
- client
- svencoop
- cstrike
- issue-259
---

# Client sound viewport and colors

## Overview

Issue #259 concerns client.dll/client.so, despite its engine hw.* wording. Five anchor batches were approved before implementation. The additions produce 91 artifacts: 56 Sven outputs (including predecessor functions), plus 35 CS-family outputs. Artifact identities follow the real ELF symbol names using the repository's class_method spelling.

## Responsibilities

- Locate client sound, viewport, HUD and text-color functions from exact strings, exact public exports, or budgeted body patterns.
- Recover true global storage through annotated references and LLM_DECOMPILE, then validate current instructions and mapped data. Disable old YAML discovery everywhere.
- Preserve platform, family, inline and ABI boundaries; do not force private Sven behavior onto engine or unrelated clients.

## Involved Files & Symbols

- ida_preprocessor_scripts/find-CClient_SoundEngine_LookupSoundBySample.py, find-CClient_SoundEngine_PlayFMODSound.py, find-WeaponsResource_SelectSlot.py: exact target-owned literals.
- ida_preprocessor_scripts/find-Sven-client-predicates.py: AllowedToPrintText, IsScoreBoardVisible, GetBorderSize.
- ida_preprocessor_scripts/find-CClient_SoundEngine_LookupSoundBySentenceIndex.py: standalone sentence-index lookup; diagnostic-owner confirmation and PlayFMODSound exclusion.
- ida_preprocessor_scripts/find-Sven-client-global-predecessors.py: HUD_Init, CHudBaseTextBlock_Print, CHudSayText_PrintText.
- ida_preprocessor_scripts/find-CHudBaseTextBlock_Print-decompiles.py, find-HUD_Init-decompiles.py, find-CHudSayText_PrintText-decompiles.py: gViewPort, CClient_SoundEngine_m_pSoundEngine, gHUD, GetClientColor.
- ida_preprocessor_scripts/find-GetClientColor-CS.py, find-GetTextColor-CS.py, find-SayTextLine_Colorize.py, find-g_LocationColor.py: CS-family color locators.
- ida_preprocessor_scripts/_client_body_patterns.py: deterministic pattern priority, ambiguity rejection, explicit-owner inspection and grouped output validation. Only patterns explicitly known to start at an entry may recover missing function metadata.
- configs/svencoop-{8948,10257}.yaml, cstrike-{3248,3647,4554,6153,8684,10210}.yaml, czero-{8684,10210}.yaml, czeror-{8684,10210}.yaml; outputs under their bin_artifacts/<tag>/client directories.
- tests/test_client_body_patterns.py: ambiguity cannot fall through; group failure cannot write earlier results; cross-boundary output requires successful inspection.

## Architecture

### Sven: all rows cover 8948/10257, Windows/Linux, client module

| Artifact | Category | Discovery and evidence |
|---|---|---|
| CClient_SoundEngine_LookupSoundBySample | func | FULLMATCH `Tried to look up sound by sample without specifying a file name.\n`; one literal and owner per target |
| CClient_SoundEngine_PlayFMODSound | func | FULLMATCH `Playing music sample '%s', offset %f.\n`; one literal and owner |
| WeaponsResource_SelectSlot | func | FULLMATCH `common/wpn_hudon.wav`; one literal and owner |
| TeamFortressViewport_AllowedToPrintText | func | Four body forms: missing menu permits text; menu IDs 2 and 5 reject it |
| CHud_GetBorderSize | func | Four body forms: convert border cvar float to int, clamp to 0..100; distinguish GetWidth/GetHeight inline copies |
| TeamFortressViewport_IsScoreBoardVisible | func | Two forms: missing scoreboard returns false; otherwise VGUI1 Panel::isVisible tail-call |
| CClient_SoundEngine_LookupSoundBySentenceIndex | func | Two forms: index <= 4095, two null checks, return sample string; diagnostic is also inlined in PlayFMODSound |
| gViewPort | gv | CHudBaseTextBlock_Print argument to AllowedToPrintText |
| CClient_SoundEngine_m_pSoundEngine | gv | Same Print body loads/stores the singleton around lazy construction |
| gHUD | gv | HUD_Init object argument passed to CHud::Init |
| GetClientColor | func | PrintText calls for default (-1), server (0), and player names; resolve ELF PLT thunks to actual callee |
| CHudBaseTextBlock_Print | func predecessor | Intersection of FULLMATCH `misc/talk.wav` and calls to validated AllowedToPrintText; the literal alone has four owners |
| CHudSayText_PrintText | func predecessor | FULLMATCH `Server Console`; unique owner |
| HUD_Init | func predecessor | Exact public export table entry and validated function start |

Patterns and their compiler coverage are recorded beside the executable lists. Member displacements and branch distances are wildcarded. VGUI1 isVisible slot 0x28 is a verified ABI fact: 8948 ELF ScorePanel vtable address point 0x301678 + 0x28 has relocation _ZN4vgui5Panel9isVisibleEv. Wildcarding this slot also matches an AngelScript getter at 0x18. This exception is restricted to these Sven clients; CS VGUI2 is unrelated.

Sven references: six official generated/annotated YAMLs under references/svencoop-10257/client, with existing family-reference fallback. Names and roles are corroborated by the 8948 ELF symbol table; 10257 is stripped. The supplied public HL source does not contain this private Sven implementation.

| Function RVA | 8948 Win | 8948 Linux | 10257 Win | 10257 Linux |
|---|---|---|---|---|
| LookupSoundBySample | 0x5a510 | 0x11bc46 | 0xd030 | 0xac352 |
| PlayFMODSound | 0x5aed0 | 0x11be60 | 0xd9f0 | 0xac5dc |
| SelectSlot | 0x54a80 | 0x1127f0 | 0x41e0 | 0x9f836 |
| AllowedToPrintText | 0xb4690 | 0x180196 | 0x6cd20 | 0x1213be |
| GetBorderSize | 0x7edb0 | 0x13f032 | 0x362d0 | 0xdb124 |
| IsScoreBoardVisible | 0xb4670 | 0x17fd52 | 0x6cd00 | 0x120f80 |
| LookupSoundBySentenceIndex | 0x5a4c0 | 0x11ae82 | 0xcfe0 | 0xab508 |
| Print | 0x9df80 | 0x16109e | 0x55d70 | 0xffbb4 |
| PrintText | 0x9e590 | 0x1602ba | 0x563e0 | 0xfef8e |
| HUD_Init | 0x563e0 | 0x1167ac | 0x8d50 | 0xa4330 |
| GetClientColor | 0x7c130 | 0x13b792 | 0x31840 | 0xd44c8 |

| Global VA | 8948 Win | 8948 Linux | 10257 Win | 10257 Linux |
|---|---|---|---|---|
| gHUD | 0x105baac8 | 0x75f4e0 | 0x105f8be0 | 0xa55980 |
| gViewPort | 0x101ba884 | 0x35f480 | 0x101f8990 | 0x655920 |
| CClient_SoundEngine_m_pSoundEngine | 0x105bcd88 | 0x761a40 | 0x105fb214 | 0xa581c0 |

For the Sven clients in the tables above, Windows base is 0x10000000 and Linux base is 0. Artifacts include gv_sig_va, gv_inst_offset, gv_inst_length and gv_inst_disp; Linux PIC outputs also retain the shared gv_pic_addend correction. These identify storage addresses, not operand-field addresses or loaded object pointers.

### CS family: client module

GetClientColor is discovered without a code-body pattern: Linux clients use the retained `_Z14GetClientColori` symbol, and Windows clients intersect code owners referring to all five known RGB float[3] arrays, excluding callers with direct calls to reject inlined UI copies. The arrays are searched independently, so their storage order can vary. The resulting function still receives a generated unique `func_sig` for the artifact contract. GetTextColor uses three patterns encoding color 3 -> player color, color 4 -> location array, other -> NULL. Both targets are func. The floats are returned through pointers, so these bodies do not offer scalar xref_floats anchors.

| Configuration | GetClientColor Win/Linux RVA | GetTextColor Win/Linux RVA | g_LocationColor Win/Linux VA |
|---|---|---|---|
| cstrike-3248 | 0x43360 / no binary | 0x5ff60 / no binary | 0x19e0790 / no binary |
| cstrike-3647 | 0x43360 / no binary | 0x5ff60 / no binary | 0x19e0790 / no binary |
| cstrike-4554 | 0x45cd0 / no binary | 0x63a30 / no binary | 0x19e7a28 / no binary |
| cstrike-6153 | 0x444b0 / 0xf9dc0 | 0x62030 / 0x1165a0 | 0x19e8930 / 0x2117d0 |
| cstrike-8684 | 0x454f0 / 0xf9f10 | 0x63380 / 0x116650 | 0x19e9a08 / 0x210f70 |
| cstrike-10210 | 0x48180 / 0xa5f10 | inline observed / 0xc4d30 | 0x10106398 / 0x1d5650 |
| czero-8684 | 0x454f0 / no binary | 0x63380 / no binary | 0x19e9a08 / no binary |
| czero-10210 | 0x48180 / no binary | inline observed / no binary | 0x10106398 / no binary |
| czeror-8684 | 0x3e2f0 / no binary | not located / no binary | not located / no binary |
| czeror-10210 | 0x3ea80 / no binary | not located / no binary | not located / no binary |

The true gv g_LocationColor (MetaHook BaseTextColor) is recovered by LLM_DECOMPILE from GetTextColor's location branch. HL25 Windows instead uses the actual parent SayTextLine_Colorize, func RVA 0x63640, located by one unique pattern encoding the inlined 3/4/NULL selection and client-index call. Each decoded data object must equal float[3] {0,0.8,0} in a non-executable mapped segment. The finder generates into temporary outputs and writes the final artifact only after this additional check, preserving any previous output on failure.

Reference gamevers are explicit: cstrike-8684 supplies both GetTextColor platforms; Windows-only czero-10210 supplies Colorize (its binary is identical to cstrike-10210 Windows). References were exported with generate_reference_yaml.py from owned, temporarily reconstructed databases, and both disasm_code and procedure were annotated. They intentionally do not fall back to a Half-Life client body.

## Dependencies

- [[idalib-mcp]] owned IdaMcpLifecycle, restored_strict warm databases, save_on_success=False. No IDB changes are saved or staged; worker shutdown and port release are lifecycle-owned.
- Shared x86 signature/operand validators, explicit function inspector, existing Sven PIC string-owner helper, and existing ELF PLT/GOT resolution.
- Source clues: D:/HLND2T_official/cl_dll/saytext.cpp:53, death.cpp, health.cpp:541; MetaHookSv private-field names are clues, not canonical identities.

## Notes

### Deliberate exclusions and compatibility

- CClient_SoundEngine_LoadSoundList and CClient_SoundEngine_m_iSentenceCount already exist from #244. The latter is a member (MetaHook maxsentences), not a new engine global. No duplicate implementation.
- SCClient_soundengine: Windows has a lazy getter but its real function name was not established; Linux inlines singleton access. User approved only the true CClient_SoundEngine::m_pSoundEngine global. Reading it does not instantiate the object.
- HL25 Windows GetTextColor has an observed inline body; no independent entry was established. Do not output the inline block or Colorize as GetTextColor.
- CZDS GetTextColor/g_LocationColor were not located; absence of a pattern/float array is not proof of nonexistence. Only GetClientColor is registered there.
- These targets do not warrant hw.dll/hw.so or unrelated hl/cof registrations. Missing client platforms have no outputs.

### Experience: exact-entry metadata and misleading owners

Trigger: a unique body pattern points at a callable entry but the warm IDB has no function, or a generic owner-backtracking helper rejects an existing tiny function. Constraint: caller heuristics can see multiple adjacent entries; the sentence diagnostic also belongs to an inline copy. Correct approach: opt into explicit-entry recovery only for a pattern proven to start at the entry, otherwise require the current decoded owner. Verify body semantics and a fresh unique signature. Sentence lookup additionally checks diagnostic ownership and excludes PlayFMODSound. Windows sentence lookup Hex-Rays produced no pseudocode after recovery; its identity was verified using the complete assembly instead. Scope: these finite x86 client builds.

### Experience: compiler and source differences

Trigger: MetaHook's constants or public source appear to imply one layout/return mapping. Constraint: player-info stride is 0x68 or 0x74 in CS and 0x1c in CZDS. CS's observed default/team 0 returns Grey despite the public source's Yellow case. CZDS maps 0/3 Yellow, 1 Blue, 2 Red, 4 Green, default Grey. Correct approach: compare actual field reads, switch tables and float arrays on every target; wildcard layout addresses and retain verified semantic bounds. Validate the emitted callee rather than a PLT stub. No new consumer ABI/schema was introduced.

### Experience: color data as a function anchor

Trigger: a new CS/CZ/CZDS client build changes the GetClientColor instruction sequence. Constraint: the MSVC selector can be copied into larger UI functions, and Linux color arrays are not laid out like Windows arrays. Correct approach: use the exact ELF `_Z14GetClientColori` symbol on Linux; on Windows, locate each of the five RGB float[3] arrays independently, intersect their IDA code-reference owners, exclude functions containing direct calls to reject inlined UI copies, then require one function and generate its unique runtime signature. Verification: all 17 registered CS-family GetClientColor node/platform combinations were rerun with `-node` and `-oldgamever none`; their artifacts remained unchanged. Scope: supported CS, CZ, and CZDS clients with retained ELF symbols or unchanged RGB values. A stripped ELF or changed colors requires new semantic evidence.

### Verification evidence

All applicable production nodes completed with oldgamever none: Sven's 36 distinct node/platform combinations and CS's 35, yielding the 91 outputs. Shared-predicate nodes were explicitly rerun with -node after extracting the helper (a -skill invocation skipped existing outputs and was not counted as rerun evidence). Generated output signatures were validated by the production analyzer. All three new shared-helper regression tests passed. Final validation: `uv run python tests/run_test_suite.py all -b --durations 10` ran 1244 tests with zero failures and 6 skips (POSIX/Linux-only, notes-CLI opt-in, and real-IDA opt-in conditions). `uv run python format_repo_files.py --check` and `git diff --cached --check` passed. All 11 g_LocationColor nodes were rerun after delaying final writes until the extra data check passed; their artifacts remained unchanged. Independent static code/coverage review found no current address or registration mismatch.

Reproduce with ida_analyze_bin.py -gamever <tag> -node client:<platform>:<finder> -oldgamever none -debug, selecting only the registered applicable nodes. Exact -node selection forces execution; do not combine it with -force_all. The initial -allgamever/-skill attempt was inapplicable because these client-specific finders are not registered in every engine config.

Binary SHA-256 (input file; 3248/3647 also list the existing decrypted analysis input):

| Input | SHA-256 |
|---|---|
| Sven 8948 Win | 5e3bd90c24e829c43344f0fe18368a71cad3c9b3405695e2489b469cf694624c |
| Sven 8948 Linux | 8b5fbb8f3533b38ab3fd53dfc6078012bc2f9259ba4e347b5bf301f3d0ebacc4 |
| Sven 10257 Win | f40e74b7a703d193188d628066660ff0ac4be2b09613ae4b7f8d2c671991e7d6 |
| Sven 10257 Linux | 50580344e1c59b3c77e8e4e52ed9f185fcec7da2da936873ec122f12c735a022 |
| CS 3248/3647 BLOB | 1dbddceb74daa150921db3f201c9ed66c2e399884bd10f5674b06e5133c455f2 |
| CS 3248/3647 decrypted | 2bc13327c5324a79872d36508d80db7c9ef74af925d50ebc9d1b45b6aef6ef7b |
| CS 4554 Win | 733d4b48a64991d2cd2a60c20d99f72b6533cc401c47f97cc0e6073bd482b6dc |
| CS 6153 Win | 221f4c8f8eb6348f90c72c11c252fcf0024d3b3032e503cfab80b3f4c5bee841 |
| CS 6153 Linux | 0d379680b7545ed352a696539a8049432651edb7056efbf2ce8354347d0feded |
| CS 8684 Win | ef7a0f40989cb79ba95d40f528534da36866892ee871147ca82e133b7a5edc3d |
| CS 8684 Linux | 40283f3e0c4b6bd21f9281304957ab93c04c60ce5f3d2794cdaf58b3c11ab798 |
| CS/CZ 10210 Win | b434b1c09b10b011be6c42e4154955da0c3ca46e95746988ebea1aa316a2a9f2 |
| CS 10210 Linux | 2e799ef31931c0f4372ff31ad30f0aab529b16461ed3b0928dfbd958183b2e5a |
| CZ 8684 Win | b017e06a5551f3db8c7c817b72a65433362d8b3c8394edb02cac919528e3f73c |
| CZDS 8684 Win | e28ef031c1810a913227fbdf8075a367a60165d209b8071a94020a448ff76286 |
| CZDS 10210 Win | 7eccfa2fd50e391dfeca4ada44110b5e6336523f9d5dd1433f043a0daecbb584 |

## Callers

- CHudBaseTextBlock_Print -> TeamFortressViewport_AllowedToPrintText; it also accesses the sound singleton.
- HUD_Init -> CHud::Init with gHUD.
- CHudSayText_PrintText -> GetClientColor (Sven).
- GetTextColor and SayTextLine_Colorize -> GetClientColor (CS); location branches reference g_LocationColor.
