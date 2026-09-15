---
title: Sys_ShutdownGame locator
type: note
permalink: goldsrc-vibesignatures/locators/sys-shutdowngame
tags:
  - locator
  - engine
  - func
---

# Sys_ShutdownGame

## Symbol

- **Name**: `Sys_ShutdownGame`
- **Category**: `func`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-Sys_ShutdownGame.py`

## Availability

- Declared in 10 engine configs: cof-5936, hl-10210, hl-3248, hl-3266, hl-3329, hl-3647, hl-4554, hl-6153, hl-8684, svencoop-10257.
- Platforms: both Windows and Linux where declared (hl-10210, hl-8684, svencoop-10257); the other seven engine tags are Windows-only configs.
- Inlined / absent: none observed. Verified on all 13 engine nodes (10 Windows + 3 Linux), including the four encrypted WON-family blobs analyzed through their `hw.decrypt.dll` sibling.

## Predecessors

- None.

## How it is located

`Sys_ShutdownGame` (`engine/sys_dll2.cpp`) carries `TRACESHUTDOWN(...)` wrappers; the macro stringifies its argument, so the exact C literal `"Sys_Shutdown()"` is referenced inside the function's own body.

1. Positive source `xref_strings: ["FULLMATCH:Sys_Shutdown()"]` maps every data reference of that exact string to its owning function. The literal is also referenced by `Sys_InitGame`, which stringifies the `TRACEINIT(Sys_Init(), Sys_Shutdown())` pair; that owner is the *other* candidate on every build.
2. `exclude_strings: ["FULLMATCH:Sys_Init()"]` removes it: `"Sys_Init()"` is owned by `Sys_InitGame` alone and is never referenced by `Sys_ShutdownGame`.
3. `FULLMATCH:` keeps `"Sys_Shutdown()"` from matching `"Sys_ShutdownMemory()"` / `"Sys_ShutdownArgv()"` and vice versa, so the two anchors stay disjoint without any substring heuristic.
4. Exactly one function must survive; the emitted `func_sig` must also resolve uniquely to it. Discovery uses the shared string-xref intersection only — no byte signature, no prior artifact and no LLM output participates.

## Pitfalls

- `Sys_ShutdownGame` and `Sys_InitGame` both reference `"Sys_Shutdown()"`; dropping the `exclude_strings` entry yields a two-candidate failure on every build, not a wrong single answer.
- On hl-8684 Windows, IDA attributes the outlined `Sys_Shutdown` body to `Sys_ShutdownGame` as a **tail chunk** at a lower address than the entry (`end_ea` excludes it). `func_size` therefore describes only the entry chunk. Any consumer that needs the callsite must walk `idautils.FuncItems`, not `[func_va, func_va + func_size)`.
- The literal is a C string; the IDB's shared string list must already be populated. The finder never sets `string_min_length`, so it does not rebuild IDB-wide string state.
