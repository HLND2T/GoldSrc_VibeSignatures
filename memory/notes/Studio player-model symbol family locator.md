---
title: Studio player-model symbol family locator
type: note
permalink: goldsrc-vibesignatures/notes/studio-player-model-symbol-family-locator
tags:
- locator
- studioapi
- player-model
- dm-playerstate
- engine
- callsite-patch
- pic
- goldsrc
---

# Studio player-model symbol family locator

## Trigger

Need the engine's player-model studio chain — `studioapi_SetupPlayerModel` (func), `R_StudioChangePlayerModel` (func, Windows only), `DM_PlayerState` (gv), `engine`/`eng` (gv) — and the `studioapi_SetupPlayerModel → R_StudioChangePlayerModel` call-site patches (SCModelDownloader redirect targets) across hl-3248..hl-10210, svencoop-10257, cof-5936.

## Facts

- `studioapi_SetupPlayerModel` = `engine_studio_api_t` slot **0x7C** (index 31, `common/r_studioint.h`). The table is recovered from `ClientDLL_CheckStudioInterface` via its unique interface-mismatch diagnostic; SvEngine words it differently (`client library` vs `client .dll`), so the svencoop finder is a `-svencoop` variant. Validated table = writable-data run of ≥43 non-zero code dwords and a function-start slot 0x7C.
- Linux .so has **two** string owners (both reference the same table): collapse on the unique table VA, not on the owner. SvEngine Linux is PIC: table VA from `lea reg, [ebx+disp32]` with the ebx GOT anchor (`add ebx, imm32` after `call thunk`, anchor RVA 0x2EE000). `is_exec(0)` must be excluded (ELF base 0 maps address 0 into .text).
- `engine` = first post-TraceInit load of a writable-data slot whose static value points at the static `CEngine g_Engine` object and which is dereferenced within a few instructions (feeds `SetQuitting(QUIT_NOTQUITTING)`, vtable +0x40 Windows / +0x44 Linux). Inlined Sys_InitArgv (hl-10210 hw.so) loads com_argc/com_argv first; those slots are zero in the image, so the non-zero-static-pointer requirement rejects them. hl-10210/svencoop Windows place `g_Engine` 8 bytes after the slot — adjacency is normal.
- `DM_PlayerState` = writable-data operand in `studioapi_SetupPlayerModel` accepted when (Form A) its 32-bit destination register is a `[reg+0x208]` base, or (Form B, hl-10210 hw.dll) the function also carries operands at V+0x104 and V+0x208 (MSVC folds the model field into an absolute displacement and indexes it directly). Element stride 0x20C on every family (hl builds stride their extended `cl.players` at 0x250 — never confuse them: only DM gets +0x208/+0x104 accesses). DM is the array itself, statically zero-filled: reject candidates whose first dword points into const/code (that is a cvar-name pointer slot like "developer").
- `R_StudioChangePlayerModel` (Windows) = the unique zero-argument direct callee of `studioapi_SetupPlayerModel` that references the same `currententity` global the owner dereferences at +0x0B94, contains the MAX_SKINS 0x0B immediate, and stores 0xFFFFFFFF. MSVC merges the two source call sites on hl-6153/8684/10210; WON-era builds, hl-4554, svencoop, and cof keep both.
- Call-site patch counts (config expected outputs): hl-3248/3266/3329/3647/4554 = **2**, hl-6153/8684/10210 = **1**, svencoop = **2**, cof = **2** — verify empirically, do not assume "newer build merges".
- Linux inline: hl-8684/10210 hw.so and svencoop hw.so inline R_StudioChangePlayerModel into the caller (0 direct calls; the standalone copy survives only because the function has external linkage). R_StudioChangePlayerModel and the callsite patches are therefore **Windows-only** registrations; DM_PlayerState/studioapi_SetupPlayerModel/engine stay cross-platform.
- Regression matrix (2026-09-09 delivery run, 13 nodes): studioapi 13/13, engine 13/13, DM_PlayerState 13/13, R_SCPM 10/10 win, callsites 10/10 win. DWARF cross-check on official .so: studioapi 0x12b380/0xc8690, DM 0x9be180/0x9a7e40, eng 0x2d6ba8/0x2bd814.

## Implementation pitfalls (all hit during the 2026-09-09 delivery)

1. **Raw byte-window dword scans false-positive**: `mov eax, [esi+208h]` opcode bytes decode into a mapped .data address (e.g. 0x0208868B) and an `imul reg, reg, 20Ch` window can too. Always extract operands via IDA structures (o_mem `addr`, o_imm `value`, o_displ `addr`); never raw-scan instruction bytes for globals.
2. **PIC o_displ ambiguity**: on a `lea reg, [ebx+idx+disp32]` the o_displ address is the module-relative disp (can land in a writable segment by chance, e.g. 0x9EC460) while the GOT-anchored resolution is the truth — when a PIC decode matches the instruction, use only it.
3. **Register reuse across forms**: a dest register matching a +0x208/+0x0B94 base set can also be the dest of an unrelated load (SvEngine "developer" lea). Require the currententity load to be a plain o_mem load (no index register) and reject pointer-to-const slots.
4. **py_eval genexpr closures**: a generator expression at module level under `exec(code, globals, locals)` cannot see loop variables from `exec_locals` (NameError: value). Put logic in functions or use explicit loops.
5. **Analyzer aborts the remaining gamevers on one skill failure** — a mid-batch error (wrong skill name for a variant) silently skips later tags (cof-5936). Re-check artifact completeness after any failed batch instead of trusting the summary.

## Correct approach

Implemented as `ida_preprocessor_scripts/_studio_player_model_common.py` + `find-studioapi_SetupPlayerModel{,-svencoop}.py`, `find-engine.py`, `find-DM_PlayerState.py`, `find-R_StudioChangePlayerModel.py`, `find-studioapi_SetupPlayerModel_to_R_StudioChangePlayerModel_CallSites.py` (the last two Windows-only via `platform: windows`), all passing `old_yaml_map=None`; registered in hl-3248..hl-10210, svencoop-10257, cof-5936 engine modules. gv artifacts use the owning-function prologue `gv_sig` convention; svencoop-linux PIC `gv_inst_disp` follows the cl_parsefuncs-linux precedent.

## 验证方式

Per-skill `ida_analyze_bin.py -allgamever -modules engine -skill find-... -debug` runs (13 Windows + Linux nodes), DWARF name cross-check on both official hw.so, `format_repo_files.py --check`, unit (664) + repository-contract suites after staging artifacts.

## 适用范围

Future player-model / studio-interface symbol requests, SCModelDownloader gamedata consumers, any finder that must distinguish DM_PlayerState from cl.players, and PIC (SvEngine Linux) global recovery work.
