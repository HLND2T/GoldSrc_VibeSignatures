---
title: Sven client gamedata migration
type: note
permalink: locators/sven-client-gamedata-migration
---

# Sven client gamedata migration (issue 367)

## Trigger and scope

AbcUi and AbcEssential migrate their Sven client/engine scans to MetaHook
ResolveGameSymbol. Production coverage is svencoop-10257 and svencoop-8948,
Windows PE32 and Linux ELF32. No plugin repositories are modified here.

## Identity and migration constraints

- `TeamFortressViewport_ShowVGUIMenu` is the VGUI1 dispatcher. 8948 ELF names
  `_ZN20TeamFortressViewport12ShowVGUIMenuE8VGUIMenu`. It rejects demo playback,
  guards intermission, walks the current-menu list, and dispatches brief/MOTD
  and Sven menu IDs. Do not substitute the different VGUI2 source body.
- `V_PunchAxis` is `ev_punchangle[axis] = punch`, confirmed by 8948 ELF's
  `_Z11V_PunchAxisif` and `D:/HLND2T_official/cl_dll/view.cpp:1678`.
- `CClient_SoundEngine_Initialize` is included despite being optional. Its own
  FMOD-version diagnostic locates initialization of Sfx/Music groups and
  `cl_spectrum_debug`. It preserves the hook entry used to capture `this`.
- The HUD array's real ELF name is **`g_PlayerExtraInfo`**, not
  `NativeHUDPanelInfo`. It includes player index 0. Debug_ShowPlayerData starts
  at player 1, reads frags/deaths/team/health/armor at 0/4/10/76/80 and advances
  by the current binary's row stride. The finder checks those fields and the
  1..32 loop bound before accepting the address operand.
- For 10257 Windows, true base = `0x10644918`, row 1 = `0x10644974`, stride =
  `0x5c`. The issue's `disp32 + 8` convention obtains **row 1**, not the global
  symbol base. `_MsgFunc_ClExtrasInfo` at `0x10032b7a` stores a **word** at
  `base + player * 0x5c + 0x54` (encoded displacement `0x1064496c`). Treat
  the consumer's `int donor`/`int admin` declaration as a consumer view,
  not a verified native type declaration.
- 8948 has stride **`0x58`**, on both platforms; 10257 has **`0x5c`** on both.
  Consumers using the real symbol should address `base + index * stride`.
  To preserve `table[index-1]`, first advance the resolved base by one row.
  A fixed 92-byte consumer struct cannot be shared with 8948 unchanged.
- `CL_GetModelByIndex` reads **`cl.model_precache`**, a client_state_t member,
  not `mod_known` or `sv.model_precache`. Verified source:
  `D:/HLND2T_official/engine/cl_main.c:3776` and `engine/client.h:374`.
  This issue publishes the requested function; no standalone model-table or
  optional punch-array record is added.

## Discovery

- `find-Sven-client-menu-punch.py`: three menu body patterns encode the
  duplicate-menu linked-list walk. Match offsets: Windows `+0x40`, 8948 Linux
  `+0x48`, 10257 Linux `+0x54`; none starts at the prologue. Three punch body
  forms cover MSVC SSE, GCC x87 and GCC SSE. The tiny setter is its own source
  statement; GCC patterns start after PIC setup. Each selected pattern has
  exactly one match/decoded owner. Old artifact signatures never locate them.
- `find-CClient_SoundEngine_Initialize.py`: exact owned FMOD-version diagnostic.
- `find-CL_GetModelByIndex.py`: exact owned diagnostic
  `fs_precache_timings: loaded model %s in time %.3f sec\n`.
- `find-g_PlayerExtraInfo.py`: exact owned printf format
  `%d %s %d %s %.2f %.2f %d %.2f %d %s\n`, followed by deterministic row-loop
  operand recovery. Shared string helpers handle stripped GCC GOTOFF xrefs.
  The three literals each have one instance and one owning function per target.
  No LLM fallback or fixed-address discovery is used.

## Verified RVAs

Linux image base is zero; client DLL base is `0x10000000`, hw.dll base is
`0x1d00000`. These numbers are evidence for the hashes below, not locators.

| Symbol | 10257 Windows | 10257 Linux | 8948 Windows | 8948 Linux |
| --- | --- | --- | --- | --- |
| TeamFortressViewport_ShowVGUIMenu | 0x6cd50 | 0x12491a | 0xb46b0 | 0x183470 |
| V_PunchAxis | 0x753d0 | 0x12dffa | 0xbca10 | 0x18c08e |
| CClient_SoundEngine_Initialize | 0xc4d0 | 0xaf396 | 0x599a0 | 0x11e58a |
| g_PlayerExtraInfo (row 0) | 0x644918 | 0xaa2ae0 | 0x606300 | 0x7ac120 |
| CL_GetModelByIndex (engine) | 0x27ec0 | 0x117e40 | 0x27e00 | 0x164b60 |

Global reference evidence (signature is the independently validated debug
owner signature; `gv_inst_offset` selects the exact operand instruction):

| Target | Instruction VA | disp offset | Embedded dword | Resolution |
| --- | --- | --- | --- | --- |
| 10257 Windows | 0x1006930c | 1 | 0x10644974 | +0xffffffa4, modulo 32 bits |
| 8948 Windows | 0x100b0e4c | 1 | 0x10606358 | +0xffffffa8, modulo 32 bits |
| 10257 Linux | 0x11707b | 2 | 0x484b3c | +PIC addend 0x61dfa4 |
| 8948 Linux | 0x17607c | 2 | 0xfffff1fc | +PIC addend 0x7acf24, modulo 32 bits |

8948 Linux's operand is a GOT slot: GOT `0x308000` + signed displacement
`-0xe04` = slot `0x3071fc`, containing `&g_PlayerExtraInfo`. The existing
artifact PIC addend encodes the verified final RVA; consumers do not expose
the GOT slot as the array. 10257 uses GOTOFF LEA for row 1, adjusted by -92.

## Binary identities (SHA-256)

| Target | SHA-256 |
| --- | --- |
| 10257 client.dll | f40e74b7a703d193188d628066660ff0ac4be2b09613ae4b7f8d2c671991e7d6 |
| 10257 client.so | 50580344e1c59b3c77e8e4e52ed9f185fcec7da2da936873ec122f12c735a022 |
| 8948 client.dll | 5e3bd90c24e829c43344f0fe18368a71cad3c9b3405695e2489b469cf694624c |
| 8948 client.so | 8b5fbb8f3533b38ab3fd53dfc6078012bc2f9259ba4e347b5bf301f3d0ebacc4 |
| 10257 hw.dll | e3c7f374b70845fb6f45c05906e4b5fe3dc9f394ab37bb653501d3b6a3282596 |
| 10257 hw.so | 8cead76a51204a4ba1036c85cc2099b7c3542950d924846a9aa2ccf619df7dfd |
| 8948 hw.dll | 22fd4d1ad0d3e11a44e7cd5643fe9f6b8ded1234cce819cc242ba5a3fd338ce8 |
| 8948 hw.so | aad1299bf2389070f9fa27a7413543e028f8b26ef50d7ecfaa11504be26e4b0e |

## Validation and session ownership

Main-session evidence uses tier 2: shared supervisor `idb_list`, exact
`idb_open(...i64)`, verified x86 identity/hash, and `idb_close(save=True)` for
every opened session (all returned `owned:true, saved:true`). No externally
managed session is saved or closed. The final IDBs are the module-local
`bin/<tag>/<module>/<binary>.i64`; binary/IDA scratch is excluded from Git.
Final IDB modification times (UTC, 2026-10-12): all four client IDBs
14:17:14; 10257 engine and 8948 hw.dll 14:20:19; 8948 hw.so 14:20:20.
The final shared-supervisor inventory is empty.

For official Analyzer replay, binary and packed IDB copies under the system
temporary directory avoid loose supervisor sidecars that the strict lifecycle
interprets as locks. The Analyzer runs all eight new nodes per tag, against
fresh isolated outputs, validates the artifacts, and closes its owned workers.
Rebuilt outputs must byte-match the 20 delivered YAMLs.

Verification commands:

```text
uv run python ida_analyze_bin.py -gamever <tag>
  -node engine:windows:find-CL_GetModelByIndex
  -node engine:linux:find-CL_GetModelByIndex
  -node client:windows:find-Sven-client-menu-punch
  -node client:linux:find-Sven-client-menu-punch
  -node client:windows:find-g_PlayerExtraInfo
  -node client:linux:find-g_PlayerExtraInfo
  -node client:windows:find-CClient_SoundEngine_Initialize
  -node client:linux:find-CClient_SoundEngine_Initialize
  -oldgamever none -bindir <isolated-inputs> -artifactdir <isolated-outputs> -debug
uv run python tests/run_test_suite.py all -b --durations 30
uv run python format_repo_files.py --check
```

Results on 2026-10-12: both tags report 8 successful nodes, zero failures and
zero skips. After tightening the array loop-bound check, both global nodes per
tag were rebuilt again successfully. Original-binary byte replay confirms
20/20 unique signatures at their declared addresses, all four decoded global
operands, and byte-identical independent rebuilds. 10257 Windows CRC-64/XZ
matches the issue: client `6ad36cd4373ebb45`, engine `f469129b520b2e16`.
Full source suite: 1519 tests, OK, 16 skips (Redis unavailable, POSIX-only and
opt-in checks). Actual commercial IDA evidence is supplied by the Analyzer
replays above. Formatting and `git diff --cached --check` pass. Quality gate:
deterministic binary replay plus existing regression tests; no shared helper,
schema, dependency or runtime contract changes, so no separate TDD fixtures.

## Lesson

Trigger: a plugin pattern derives an array view from a field displacement.
Root constraint: encoded field address, real symbol base, and first active row
can all differ; old builds may also have different row sizes.
Correct approach: use the real ELF identity, verify field reads and index/stride
dataflow, publish row-0 storage, and document the consumer view separately.
Validation: replay the operand using artifact resolution metadata, compare to
the named ELF symbol when present, and rebuild on every supported binary.
Applicable scope: indexed native arrays and private client/engine gamedata.
