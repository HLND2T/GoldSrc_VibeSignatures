---
title: cvar_callbacks locator
type: note
permalink: goldsrc-vibesignatures/notes/cvar-callbacks-locator
tags:
- cvar_callbacks
- cvar_hooks
- Cvar_Set
- gv-finder
---

# cvar_callbacks locator

## Trigger
Need the HL25 cvar hook list head (`cvarhook_t *cvar_hooks`, MetaHook name `cvar_callbacks`) in `hw.dll` / `hw.so`.

## Facts
- Official leak `engine/cvar.c` has no hook list. HL25 adds `cvarhook_t { hook, cvar, next }` and `Cvar_HookVariable`.
- Linux DWARF/symtab name is `cvar_hooks` (4-byte `.bss` next to `cvar_vars`). Artifact / MetaHook name is `cvar_callbacks`.
- Exists only on `hl-8684` and `hl-10210`. Absent from older `hl-*`, SvEngine, and CoF.
- `FULLMATCH:Cvar_Set: variable %s not found\n` is unique on Windows (1 owner) and shared on Linux (3–4 owners: `Cvar_Set`, inlined `Cvar_SetValue`, `Cvar_CommandWithPrivilegeCheck`).
- `Cvar_Set` is the unique owner whose only C-string data ref is that diagnostic.
- After `Cvar_DirectSet` (`FULLMATCH:***PROTECTED***`), `Cvar_Set` loads the list head (`mov eax, [abs]`, 5 bytes, disp 1). Linux also loads `cvar_vars` *before* that call; do not take the first absolute load.
- Consumer needs the **global value** (list-head pointer), not a code-operand field.

## Correct approach
1. `find-Cvar_Set`: unique error string + sole C-string filter.
2. `find-cvar_callbacks`: first non-executable 32-bit absolute load after the `Cvar_DirectSet` call.
3. Runtime: `gv = *(uint32_t *)(match + gv_inst_offset + gv_inst_disp)`.

## Verification
`-gamever hl-10210` / `hl-8684` `-modules engine -skill find-Cvar_Set` then `-skill find-cvar_callbacks` `-platform windows,linux`: 2/0/0 each.

| Binary | Cvar_Set | cvar_callbacks | insn |
| --- | --- | --- | --- |
| hl-10210 hw.dll | `0x101be0b0` | `0x104b74c8` | `0x101be0e1` |
| hl-10210 hw.so | `0x96fc0` | `0x2d4a40` | `0x9701d` |
| hl-8684 hw.dll | `0x1d2e850` | `0x1ff5710` | `0x1d2e883` |
| hl-8684 hw.so | `0xffad0` | `0x2ee2a0` | `0xffb2d` |

## Scope
`hl-8684` and `hl-10210` engine only. Not cstrike (no engine), not svencoop/cof/older hl.
