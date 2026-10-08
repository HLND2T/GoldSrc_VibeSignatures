---
title: COM_InitArgv, com_argc and com_argv locator
type: note
permalink: goldsrc-vibesignatures/locators/com-init-argv-com-argc-and-com-argv-locator
tags:
- locator
- engine
- func
- gv
---

# COM_InitArgv, com_argc and com_argv

Issue [#344](https://github.com/HLND2T/GoldSrc_VibeSignatures/issues/344) supplies the three
engine symbols behind MetaHook's `Sys_InitArgv` hook (downstream MetaHook #7).

## Symbol

- **Names**: `COM_InitArgv` (`func`), `com_argc` (`gv`), `com_argv` (`gv`)
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-COM_InitArgv.py`
- **Outputs**: `COM_InitArgv.{platform}.yaml`, `com_argc.{platform}.yaml`, `com_argv.{platform}.yaml`
- **Source**: `engine/sys_dll2.cpp::Sys_InitArgv` and `engine/common.c::COM_InitArgv`.

## Availability

- Declared in all 11 engine configs: hl-3248, hl-3266, hl-3329, hl-3647, hl-4554, hl-6153,
  hl-8684, hl-10210, cof-5936, svencoop-8948, svencoop-10257.
- Platforms: Windows + Linux (15 configured pairs; Linux for hl-8684, hl-10210,
  svencoop-8948, svencoop-10257).
- Always present; never inlined. Only the access/PLT encoding changes per build.

## Predecessors

- `Sys_InitArgv.{platform}.yaml` (produced by `find-Sys_InitArgv`), consumed via
  `expected_input`. The finder revalidates it with `inspect_owner_artifact`, so a missing or
  mismatched artifact fails closed before any discovery.

## How it is located

One deterministic walk; no LLM, no byte signature, no prior artifact signature.

1. **COM_InitArgv** is the single *real* callee of the revalidated `Sys_InitArgv` body.
   `local_call_target` resolves GCC PLT stubs through their GOT slot, so the real body is
   reached; PIC `__x86.get_pc_thunk.*` helpers are excluded by name and by the two-instruction
   `mov reg,[esp]; ret` shape. Requires exactly one remaining callee.
2. **com_argc / com_argv** are the two writable globals that `Sys_InitArgv` copies *out* of the
   engine argument store (`host_parms.argc = com_argc; host_parms.argv = com_argv;`). The
   candidate set is `(globals Sys touches) - (globals Sys writes) ∩ (globals COM writes)`, which
   must be exactly two. COM_InitArgv writes `com_argc` in its counting and `-safe` loops but
   assigns `com_argv` exactly once, so **the more frequently written global is `com_argc`**;
   ties fail closed.
3. The artifact's `gv_inst_*` come from the first displacement-carrying store of the chosen global
   inside COM_InitArgv, so `gv_sig`/`gv_sig_va` anchor on COM_InitArgv's body.

## Pitfalls

- **Do not anchor COM_InitArgv on its `-safe` literal.** The five SvEngine bodies
  (svencoop-8948 both platforms, svencoop-10257 both platforms, and — while its DWARF names are
  stripped — hl-8684 Linux) have no `safe` handling and no `command_line` rebuild; their
  COM_InitArgv only copies argv into the engine store. The hl-10210/cof and old-hl builds do have
  `-safe`. The single-callee anchor covers every build uniformly.
- **The `-safe` literal is not always an IDA string.** hl-8684 Linux compares `'-'` as an
  immediate and loads `safe` at literal+1 through an indexed byte array, so no string item and no
  direct data ref at the literal start exist. A raw `b'-safe\x00'` scan must probe both the hit and
  hit+1 to recover the owner.
- **PIC operand resolution.** svencoop Linux stores are `mov ds:(com_argc - GOTBASE)[ebx], reg`;
  the dword embedded in the instruction is the addend, not the VA. The runtime emits
  `gv_pic_addend` (0x33a000 for svencoop-8948 Linux, 0x2ee000 for svencoop-10257 Linux). Keep it.
- **Export the global's address, not its value.** On Windows the `host_parms` member stores are
  consecutive (`[member]=argc`, `[member+4]=argv`); on Linux they can be `argc` then `argv`
  (hl-10210) or `argv` then `argc` (hl-8684). Never infer argc/argv from the member order — use
  the COM_InitArgv write counts.
- Old BLOB Windows builds (hl-3248/3266/3329/3647) are analyzed through `hw.decrypt.dll`;
  `find-Sys_InitArgv`'s RunListenServer owner resolves in that database.

## Evidence (illustrative, never finder constants)

`find-COM_InitArgv` run on all 15 engine/platform pairs, 0 failed. COM_InitArgv (first entry per
family): hl-10210 win `0x101b7de0`, hl-10210 lin `0x94980`, hl-8684 lin `0xfd4a0`,
svencoop-10257 lin `0x617b0`, svencoop-8948 lin `0xb05c0`. The Linux IDBs carry DWARF names
(`COM_InitArgv`, `com_argc`, `com_argv`) which independently confirm every selection.

## Verification

- `uv run python ida_analyze_bin.py -allgamever -modules engine -skill find-COM_InitArgv -platform windows,linux -debug`
  → Successful 13, Failed 0, Skipped 2 (hl-10210 already materialized).
- `uv run python format_repo_files.py --check` → clean.
- `uv run python tests/run_test_suite.py unit -b` → 1409 tests OK (9 environment/opt-in skips).
- `uv run python tests/run_test_suite.py repository-contract -b` → 15 tests OK (after staging the
  new tracked `bin_artifacts/` inventory).
