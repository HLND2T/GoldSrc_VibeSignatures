---
title: cvar_hooks locator
type: note
permalink: goldsrc-vibesignatures/notes/cvar-hooks-locator
tags:
- cvar_hooks
- Cvar_Set
- gv-finder
---

# cvar_hooks locator

## Trigger
Need the HL25 cvar hook list head (`cvarhook_t *cvar_hooks`) in `hw.dll` / `hw.so`.

## Facts
- Official leak `engine/cvar.c` has no hook list. HL25 adds `cvarhook_t { hook, cvar, next }` and `Cvar_HookVariable`.
- Linux DWARF/symtab and the generated artifact name are `cvar_hooks` (4-byte `.bss` next to `cvar_vars`). The older artifact name was `cvar_callbacks`.
- Exists only on `hl-8684` and `hl-10210`. Absent from older `hl-*`, SvEngine, and CoF.
- `FULLMATCH:Cvar_Set: variable %s not found\n` is unique on Windows (1 owner) and shared on Linux (3–4 owners: `Cvar_Set`, inlined `Cvar_SetValue`, `Cvar_CommandWithPrivilegeCheck`).
- `Cvar_Set` is the unique owner whose only readable string data ref is that diagnostic; compare referenced addresses and raw string bytes rather than dropping non-ASCII text.
- `find-Cvar_DirectSet` already anchors `FULLMATCH:***PROTECTED***`; reuse its artifact instead of resolving that string again.
- `Cvar_Set` has one direct call to `Cvar_DirectSet`. Its immediate fall-through instruction loads the list head (`mov reg32, [abs32]`, 5 bytes, disp 1) from writable non-executable data.
- The reachable hook loop compares node `+4` with the changed `cvar_t *`, advances through node `+8`, and invokes the callback at node `+0`.
- Linux also loads inlined `cvar_vars` *before* the DirectSet call; do not take the first absolute load in the function.
- Consumer needs the **global value** (list-head pointer), not a code-operand field.
- Agent-produced YAML must normalize `gv_va`, `gv_rva`, `gv_sig_va`, `gv_inst_offset`, `gv_inst_length`, and `gv_inst_disp` as quoted hexadecimal strings before runtime validation.

## Correct approach
1. `find-Cvar_Set`: unique error string + sole C-string-address filter.
2. `find-Cvar_DirectSet`: existing exact `***PROTECTED***` string finder.
3. `find-cvar_hooks`: unique direct call, immediate writable absolute load, then reachable `+4/+8/+0` hook-loop validation; preserve the DWARF name `cvar_hooks` in IDA and YAML.
4. Runtime: `gv = *(uint32_t *)(match + gv_inst_offset + gv_inst_disp)`.
5. Agent fallback: `.claude/skills/find-cvar_hooks/SKILL.md` confirms the same global from both `Cvar_Set` dispatch and `Cvar_HookVariable` registration semantics when the strict assembly shape moves.

## Verification
- `hl-10210` / `hl-8684` `find-Cvar_Set`, Windows + Linux: `2/0/0` each.
- `hl-8684` `find-Cvar_DirectSet`, Windows + Linux: `2/0/0`.
- `hl-10210` / `hl-8684` `find-cvar_hooks`, Windows + Linux: `2/0/0` each.
- Before the rename, regenerated `Cvar_Set` and legacy `cvar_callbacks` YAML files were byte-identical to the prior verified artifacts.
- Agent-only fallback (`-skip_pp`) on `hl-10210`, Windows + Linux: `2/0/0`; both platforms independently confirmed dispatch and registration semantics.

| Binary | Cvar_Set | cvar_hooks | insn |
| --- | --- | --- | --- |
| hl-10210 hw.dll | `0x101be0b0` | `0x104b74c8` | `0x101be0e1` |
| hl-10210 hw.so | `0x96fc0` | `0x2d4a40` | `0x9701d` |
| hl-8684 hw.dll | `0x1d2e850` | `0x1ff5710` | `0x1d2e883` |
| hl-8684 hw.so | `0xffad0` | `0x2ee2a0` | `0xffb2d` |

## Scope
`hl-8684` and `hl-10210` engine only. Not cstrike (no engine), not svencoop/cof/older hl.
