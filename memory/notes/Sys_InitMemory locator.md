---
title: Sys_InitMemory locator
type: note
permalink: goldsrc-vibesignatures/notes/sys-init-memory-locator
tags:
- locator
- sys-initmemory
- heap
- anchor
- goldsrc
---

# Sys_InitMemory locator

## Trigger

Need the engine heap-init root function (`Sys_InitMemory`, `engine/sys_dll2.cpp`) in `hw.dll` / `hw.so` — e.g. as the bounded-disassembly root for collecting heap-limit immediates (MetaHookSv `Plugins/HeapPatch` `gPrivateFuncs.Sys_InitMemory`).

## Facts

- **真实名称**: `Sys_InitMemory` is the real engine name. hl-10210 `hw.so` is unstripped with DWARF: symtab `_Z14Sys_InitMemoryv` (C++ mangled, `sys_dll2.cpp:538` in that build), LOCAL FUNC @ `0x000d69c0` size 460; DWARF `DW_AT_name Sys_InitMemory`, `DW_AT_MIPS_linkage_name _Z14Sys_InitMemoryv`, low_pc `0xd69c0`. Adjacent `_Z18Sys_ShutdownMemoryv` @ `0xd6b90`.
- Official source role (HLND2T `engine/sys_dll2.cpp`): OS memory query, optional `"Available memory less than 15MB!!! %i\n"` fatal check, clamp `host_parms.memsize` to MINIMUM/MAXIMUM memory, per-heap-limit immediates in body.
- String forms differ per engine family:
  - GoldSrc/HL25/cof (Windows and HL25 Linux): exact `"Available memory less than 15MB!!! %i\n"` (cof keeps it in `.data`, not `.rdata`).
  - SvEngine Windows: `"Available memory less than the %.2f MB requirement (%.2f MB).\nCheck your hardware against the system requirements.\n"`.
  - SvEngine Linux: **no "Available memory" string at all**; the Linux branch instead references `"/proc/meminfo"` (unique string, unique owner in svencoop-10257 hw.so).
- Regression evidence (one owner per binary, all exact-unique):

| Build | Platform | anchor | func_va | RVA | size | prologue | heap imms |
| --- | --- | --- | --- | --- | --- | --- | --- |
| hl-10210 | win | exact 15MB string | `0x10220a90` | `0x220a90` | 0x387 | `55 8B EC 81 EC BC…` | 128MB ×3 + 40MB |
| hl-10210 | linux | exact 15MB string | `0x0d69c0` (`_Z14Sys_InitMemoryv`) | `0xd69c0` | 0x1cc | `83 EC 2C …` (no EBP frame) | 128MB ×4 |
| svencoop-10257 | win | `FULLMATCH:Available memory less than the %.2f MB requirement (%.2f MB).\nCheck your hardware against the system requirements.\n` | `0x1dbc390` | `0xbb390` | 0x30d | `55 8B EC 83 E4 C0 81 EC B4…` | 512MB ×5 |
| svencoop-10257 | linux | `FULLMATCH:/proc/meminfo` | `0xb0ea0` | `0xb0ea0` | 0x39c | `55 57 56 53 E8…` PIC | 512MB ×7 |
| cof-5936 | win | exact 15MB string | `0x1df4408` | `0xf4408` | 0x17a | `55 8B EC 83 EC 28…` | 128MB ×5 + 40MB |

- hl-10210 hw.dll ref site `0x10220c3c`: `push offset aAvailableMemor; call Sys_Error; add esp, 8` — callee matches the tracked `Sys_Error` artifact (`0x1021fc20`), confirming the MetaHookSv `push imm32; call rel32` shape.
- Sharable constraint: heap-limit immediate family in body — SvEngine 0x20000000 (512MB); GoldSrc 0x2000000/0x2800000/0x8000000 by buildnum (cof-5936 shows both 0x2800000 and 0x8000000 despite buildnum < 6153, so a future patch collector should not gate 0x8000000 on buildnum >= 6153).

## Correct approach
1. Windows (all hl-*/cof-*, incl. blob gamevers via their decrypted `hw.decrypt.dll`): `xref_strings` with `FULLMATCH:Available memory less than 15MB!!! %i\n`.
2. hl Linux (hl-10210 AND hl-8684): `FULLMATCH:-heapsize` — the 15MB wording exists only in HL25-era Linux builds (hl-8684 hw.so drops it and instead parses `-heapsize`/`-minmemory` plus `"Unable to allocate %.2f MB\n"`; all three are uniquely owned by `_Z14Sys_InitMemoryv` in both builds).
3. SvEngine Windows: `FULLMATCH:Available memory less than the %.2f MB requirement (%.2f MB).\nCheck your hardware against the system requirements.\n`; SvEngine Linux: `FULLMATCH:/proc/meminfo` (verify single string / single owner in the current IDB).
4. Validate owner via in-body heap-limit immediates family and a `Sys_Error` call at the string site (Windows).

Implemented as `ida_preprocessor_scripts/find-Sys_InitMemory.py` (generic, platform-branched anchors) and `find-Sys_InitMemory-svencoop.py` (svencoop), both passing `old_yaml_map=None`; registered in all engine-declaring configs (hl-3248..hl-10210, cof-5936, svencoop-10257). 2026-09-06 delivery run: 13/13 platform nodes green (hl-8684 linux resolves `0x139c90` = symtab `_Z14Sys_InitMemoryv`; hl-3248's inlined form has no EBP frame, prologue `83 EC 24`).
## 验证方式

Owned `IdaMcpLifecycle` per binary (`restored_strict`), `survey_binary` + `server_health`, py_eval string/xref/owner/immediate probe; require owner_count == 1 and cross-platform source-role agreement (2026-09-06 run: 5/5 binaries passed; IDBs closed clean, no `.id0` locks).

## 适用范围

`find-anchor-to-goldsrc-symbol` requests for `Sys_InitMemory`, future `find-Sys_InitMemory` preprocessor design, HeapPatch-style heap-limit patch collectors. SvEngine Linux has no memory-shortage string — never assume the 15MB literal exists on every platform.