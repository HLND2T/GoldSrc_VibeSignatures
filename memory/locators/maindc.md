---
title: maindc locator
type: note
permalink: goldsrc-vibesignatures/locators/maindc
tags:
  - locator
  - engine
  - gv
---

# maindc

## Symbol

- **Name**: `maindc`
- **Category**: `gv`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-Sys_InitGame.py`
- **Source**: `engine/gl_vidnt.c`, `HDC maindc`. Linux ELF name is `maindc` (4-byte `.bss` object). SDL builds still pass `&maindc` into `GL_SetMode`.

## Availability

- Same coverage as `Sys_InitGame`: all 11 engine configs, every declared platform, including Linux SDL engines.

## Predecessors

- Located in the same run as `Sys_InitGame`. No YAML `expected_input`.

## How it is located

The unique `GL_SetMode` / `GL_SetModeLegacy` call in `Sys_InitGame` takes `&maindc` as arg1 and `&baseRC` as arg2. GoldSrc/HL25 use the six-arg form with `"opengl32.dll"`; SvEngine uses the three-arg form. The artifact is the object whose *address* is arg1.

The `gv_sig` instruction is the `push offset` / `mov offset` / PIC `lea` that materializes `&maindc`.

## Pitfalls

- Do not pick arg2 (`baseRC`) or assign by `.bss` adjacency. Windows often lays out `baseRC` then `maindc`; hl-10210 Linux is `maindc` then `baseRC`; svencoop-8948 Linux is `maindc`, `baseRC`, `pmainwindow`.
- `Sys_Shutdown` / `Sys_ShutdownGame` pass `maindc` by value into `GL_Shutdown`. That load is a different operand role.
- This is a real global on Linux SDL even when the stored HDC is unused.
