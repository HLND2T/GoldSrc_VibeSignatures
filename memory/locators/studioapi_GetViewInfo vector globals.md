---
title: studioapi_GetViewInfo vector globals
type: note
permalink: goldsrc-vibesignatures/memory/locators/studioapi-get-view-info-vector-globals
tags:
- locator
- engine
- func
- gv
---

# studioapi_GetViewInfo vector globals

## Overview and responsibilities

Issue #198 adds engine/func `studioapi_GetViewInfo` and engine/gv `vup`, `vright`, `vpn`. Existing `r_origin` coverage spans all 15 binaries; it is a corroborating input only. The user approved a deterministic implementation instead of LLM_DECOMPILE.

## Files and dependencies

- `ida_preprocessor_scripts/find-studioapi_GetViewInfo.py`: reuse the existing studio diagnostic/table locator; validate complete copy semantics and write the function.
- `ida_preprocessor_scripts/find-studioapi_GetViewInfo-globals.py`: inputs `studioapi_GetViewInfo.{platform}.yaml` and `r_origin.{platform}.yaml`; emit the three new globals together.
- `ida_preprocessor_scripts/_studio_view_info.py`: bounded symbolic interpreter and current-IDB operand adapter.
- Existing `_studio_player_model_common.locate_studio_slot`, `_engine_private_globals_common.run_walk`, `_direct_gv_common.inspect_owner_artifact` / `write_located_globals` and signature/PIC validators remain unchanged.
- `tests/test_studio_view_info.py`: synthetic behavioral and adapter regressions, not source-text/config/artifact assertions.
- Source: `D:/HLND2T_official/common/r_studioint.h:9-36`, `engine/r_studio.c:5081-5086`.

## Anchor and architecture

Exact studio-interface diagnostic (GoldSrc/HL25/CoF or SvEngine wording) -> unique validated engine_studio_api table -> slot 12, byte offset 0x30 -> GetViewInfo. There is one matching diagnostic per binary. Windows has one owner; each Linux input has two owners referencing the same table. Existing table validation requires >=43 code pointers; 45 were observed. No old signature or byte pattern participates in discovery.

The function copies four float[3] objects to output parameters: r_origin, vup, vright, vpn. Track stack/frame pointers, argument pointers, GPR/XMM scalar values, x87 values and source-address provenance. Require exactly twelve writes, offsets 0/4/8 for every output, contiguous source components, four nonoverlapping vectors and a balanced return. Match the first vector against the existing r_origin artifact. Reject unknown instructions, branches/calls beyond the exact initial get-PC thunk, indexed/FS/GS accesses, partial widths, ambiguous provenance, extra writes and incomplete copies. Neither instruction order nor global address order determines role.

The direct-GV exception is justified by this complete copy proof on every supported binary. GV artifacts reuse the unique owner signature and carry gv_inst_offset to the originating scalar/address-load instruction. Existing resolution validation derives PIC metadata.

## Names, ABI and coverage

- HL8684/10210 ELF contains studioapi_GetViewInfo and the exact global names r_origin/vup/vright/vpn.
- Sven8948 ELF raw function name is `_Z21studioapi_GetViewInfoPfS_S_S_`; use the repository's demangled artifact identity studioapi_GetViewInfo. Globals retain their ELF names.
- Sven10257 ELF is stripped; slot and full copy semantics agree with the source and Sven8948.
- Sven8948 Linux obtains vector addresses through GOT slots; Sven10257 uses GOTOFF LEAs. Emit vector storage, never a GOT cell. Existing gv_pic_addend supports both.
- Windows: hl-3248/3266/3329/3647/4554/6153/8684/10210, svencoop-8948/10257, cof-5936. Linux: hl-8684/10210 and svencoop-8948/10257.
- Legacy BLOB inputs use existing hw.decrypt.dll analysis images. No binaries were rebuilt or committed. No missing/inlined targets; Windows-only tags do not claim Linux coverage. Client-only CS/CZ configs have no engine module.

## Representative evidence (VA only, never discovery constants)

| Binary | GetViewInfo | vup | vright | vpn |
|---|---|---|---|---|
| HL10210 Windows | 0x101f3ba0 | 0x10dc55a0 | 0x10dc5580 | 0x10dc5590 |
| HL10210 Linux | 0xc6280 | 0xf7d980 | 0xf7d784 | 0xf7d76c |
| Sven8948 Linux | 0xee7c0 | 0x30d6d64 | 0x30d6d4c | 0x30d6d58 |
| Sven10257 Linux | 0x9fcd0 | 0x30f6f04 | 0x30f6eec | 0x30f6ef8 |
| HL3248 Windows | 0x1d927b0 | 0x2c20170 | 0x2c20280 | 0x2c20160 |
| CoF5936 Windows | 0x1dc3a35 | 0x2c0e3f0 | 0x2c0e500 | 0x2c0e3e0 |

## Validation and reusable lessons

- Investigation: owned IdaMcpLifecycle sessions validated exact input identity, survey/health, normal save/close, final IDB mtime and port release. SHA256, VA/RVA, raw bodies and operand offsets for all 15 inputs are in local scratch `C:/Users/HZDEV/AppData/Local/Temp/issue198-evidence/`.
- Final selected batch: `uv run python ida_analyze_bin.py -batch_selection C:/Users/HZDEV/AppData/Local/Temp/issue198-selection.json -batch_diagnostics C:/Users/HZDEV/AppData/Local/Temp/issue198-batch -debug`. All 15 binary work items / 30 nodes succeeded. It forced both finders to execute, including previously generated function artifacts. Consumer IDBs use strict restored/no-save policy.
- Independent PE/ELF audit passed 60 artifacts: preimplementation addresses, SHA256, unique signature matches across mapped segments, writable 12-byte storage, owner boundaries, selected instruction agreement and operand decoding with ELF relocations/PIC metadata.
- Trigger: HL25 initially rejected MOVSS. Root cause: IDA reports the entire 16-byte XMM register even for scalar MOVSS. Correct approach: track a 4-byte scalar lane for MOVSS only. Verification: adapter regression reproduces the actual dtype.
- Trigger: Sven Windows initially rejected operand type 11. Root cause: IDA prepends a hidden st(0) operand before the displayed FLD/FSTP memory operand. Correct approach: skip hidden x87 operands and model the x87 stack explicitly; preserve the real memory operand displacement. Verification: adapter fixture includes hidden operand zero.
- Scope: straight-line vec3-copy accessors only; unfamiliar compiler transformations fail closed instead of guessing.

## Final repository checks (2026-09-22)

- `uv run python tests/run_test_suite.py all -b --durations 30`: exit 0, 1010 tests in 102.671s, OK with 6 environment/opt-in skips (2 notes CLI smoke tests, 3 Redis integration setup classes, 1 opt-in IDA test). Real commercial IDA execution was independently covered by the 15-binary selected batch.
- `uv run python format_repo_files.py --check`: exit 0, including all 60 new YAML artifacts.
- `git diff --check`: exit 0.
- Eleven new behavior tests include interleaved/reordered copies, scalar/SSE/x87/PIC provenance, malformed components, unsupported control flow/addressing, invalid GOT pointees and stack balancing.
