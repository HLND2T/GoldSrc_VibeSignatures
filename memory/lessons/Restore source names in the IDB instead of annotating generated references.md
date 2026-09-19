---
title: Restore source names in the IDB instead of annotating generated references
type: note
permalink: goldsrc-vibesignatures/lessons/idb-symbol-restore-for-reference-generation
tags:
  - lesson
  - preprocessor
  - gv
  - llm-decompile
  - idb
---

# Restore source names in the IDB instead of annotating generated references

## Trigger

An `LLM_DECOMPILE` reference is being prepared for a **Windows PE** function whose body
references globals and callees that IDA renders as `dword_XXXXXXXX` / `sub_XXXXXXXX`. The
applied workflow says to "rename known symbols in both `disasm_code` and `procedure`", so the
generated YAML is hand-edited patch by patch.

## Root cause / constraint

Hand annotation is stored only in the generated file and is destroyed by the next
`generate_reference_yaml.py` run, so it is neither durable nor reusable, and the same names must
be re-derived for every future regeneration. The names belong to the IDB, not to the reference.

Two hard constraints decide how the restoration must be performed:

1. `generate_reference_yaml.autostart_mcp_session` builds its lifecycle with
   `save_on_success=False`. **Any rename performed during reference generation is discarded when
   the worker exits.** The restoration has to run in a separate owned lifecycle that saves.
2. `IdaMcpLifecycle.__exit__` only saves when the run ends without an exception, the worker is
   owned (`_force_local_stop == False`) and `save_on_success` is true, so the renames must be
   driven from synchronous code with `run_mcp_operation(...)` around a `py_eval` phase.

## Correct approach

- Drive the restoration with `with IdaMcpLifecycle(binary, platform, host, None, [], debug,
  database_policy=DATABASE_POLICY_RESTORED_STRICT, save_on_success=True)` and do the mutation
  inside `run_mcp_operation(phase())`; call `server_health` before leaving the block.
- Derive the names from independent evidence, not from guesswork: `nm -a` on a **non-stripped
  Linux peer of the same source revision** gives the real symbols to mirror onto the Windows
  binary (`Mem_Malloc`, `GL_GenTexture`, `LoadBMP8`, `LoadTGA2`, `Q_strcpy`, `Q_strcmp`,
  `GL_IsTextureValid`, `r_missingtexture`, `suf`, `texgammatable`, `movevars`). `__x86.get_pc_thunk.*`
  is a PIC thunk IDA named, not a source function.
- Verify a rename by rendering the **referencing instruction** with
  `idc.generate_disasm_line(insn_va, 0)`. `idc.get_name(ea)` / `ida_name.get_ea_name(ea)` return
  `""` for some `.data` addresses even though the disassembly renders the name, so a
  `get_name`-based guard silently skips correct renames and cannot be used as the check.
- Setting an array type needs the full declaration (`int gSkyTexNumber[6];`) and a preceding
  `ida_bytes.del_items(ea, ida_bytes.DELIT_SIMPLE, size)`; re-apply `set_name` afterwards because
  `SetType` can drop it. IDA rewrites dots in names (`movevars.skyName`) to underscores in some
  paths, which is cosmetic only.
- After the save, regenerate the references and confirm the names are present in the emitted
  `disasm_code`/`procedure`; the produced artifacts must not change, because instruction selection
  and signatures do not depend on IDB names.

## 同一 family 不同 build 的地址不可互相复制

While restoring `svencoop-10257`, two `.data` addresses were copied from the `svencoop-8948`
analysis because the two DLLs have near-identical bodies. They are **not** the same addresses
(8948 `textures`/`gLoadSky` at `0x80068f0`/`0x8006908`, 10257 at `0x8046a94`/`0x8046aac`), so the
rename landed on an unreferenced slot and the real global kept its old name. Always re-read the
operand of a `mov reg, offset <global>` / `cmp <global>, imm` in the **current** IDB; a cross-build
address is evidence for the role, never for the address.

## Verification

- `idc.generate_disasm_line` on the referencing instruction shows the source name after the save
  (re-checked in a fresh lifecycle, so the saved state is what is being read).
- Regenerated references read like source (`cmp gLoadSky, 0`, `mov esi, offset gSkyTexNumber`,
  `call Q_snprintf`) with no hand edits.
- The LLM-produced artifacts for the same run match the independent disassembly evidence and, on
  builds that keep `.symtab` (`svencoop-8948/hw.so`), match the real symbol addresses exactly
  (`gLoadSky 0x34d8034`, `gSkyTexNumber 0x34d8040`).

## Scope

Any Windows PE reference generation where a Linux peer of the same revision keeps `.symtab`, and
more generally any workflow that wants IDB names to survive regenerations. The IDB itself lives
in the untracked `bin/` submodule, so the durable deliverable remains the committed reference
YAML; the restoration makes regeneration reproducible rather than required.
