---
title: Sys_InitGame locator
type: note
permalink: goldsrc-vibesignatures/locators/sys-initgame
tags:
  - locator
  - engine
  - func
---

# Sys_InitGame

## Symbol

- **Name**: `Sys_InitGame`
- **Category**: `func`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-Sys_InitGame.py` (also emits `pmainwindow` and `maindc`)
- **Source**: `engine/sys_dll2.cpp`, `int Sys_InitGame(char *lpOrgCmdLine, char *pBaseDir, void *pwnd, int bIsDedicated)`. Linux ELF name is `_Z12Sys_InitGamePcS_Pvi`.

## Availability

- Declared in all 11 engine configs: cof-5936, hl-3248, hl-3266, hl-3329, hl-3647, hl-4554, hl-6153, hl-8684, hl-10210, svencoop-8948, svencoop-10257.
- Platforms: Windows + Linux where the config declares `hw.so`.
- Inlined / absent: never absent. On hl-10210 Windows, `Sys_InitMemory` is inlined into this function, so the existing `Sys_InitMemory` artifact shares this entry VA.

## Validation evidence

`ida_analyze_bin.py -modules engine -skill find-Sys_InitGame` produced 15/15 engine nodes (11 Windows + 4 Linux). Representative VAs:

| Build | Platform | `Sys_InitGame` | `pmainwindow` | `maindc` |
| --- | --- | --- | --- | --- |
| hl-10210 | Windows | `0x10220a90` | `0x1063d9f8` | `0x10539084` |
| hl-10210 | Linux | `0xd6db0` | `0x824860` | `0x33816c` |
| hl-8684 | Linux | `0x139fb0` | `0x83a4a0` | `0x351ca4` |
| svencoop-10257 | Linux | `0xb1700` | `0xd3fbd0` | `0xd3fbc8` |
| svencoop-8948 | Linux | `0x100130` | `0xd8d190` | `0xd8d188` |
| cof-5936 | Windows | `0x1df4709` | `0x24e0754` | `0x2499fa8` |

## Predecessors

- None. `find-Sys_InitGame` has no `expected_input` and passes `old_yaml_map=None`.

## How it is located

`TRACEINIT(Sys_InitLauncherInterface(), Sys_ShutdownLauncherInterface())` stringifies both arguments. The exact C literal `"Sys_InitLauncherInterface()"` is referenced only inside `Sys_InitGame`.

1. `exact_string_owner("Sys_InitLauncherInterface()")` requires one string instance and one owning function.
2. `"Sys_ShutdownLauncherInterface()"` is also referenced by `Sys_ShutdownGame` and is not a discovery anchor.
3. The emitted `func_sig` must resolve uniquely to that owner.

## Pitfalls

- Dropping `FULLMATCH:` would let `"Sys_InitLauncherInterface()"` collide with no sibling today, but the shutdown twin `"Sys_ShutdownLauncherInterface()"` *does* have two owners; keep exact match.
- cof-5936 starts at an odd VA (`push ebp`). Treat it as a normal function start.
- hl-10210 Windows: do not retarget `find-Sys_InitMemory`; that finder still locates the inlined body via its 15MB diagnostic.
