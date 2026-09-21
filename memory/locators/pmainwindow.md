---
title: pmainwindow locator
type: note
permalink: goldsrc-vibesignatures/locators/pmainwindow
tags:
  - locator
  - engine
  - gv
---

# pmainwindow

## Symbol

- **Name**: `pmainwindow`
- **Category**: `gv`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-Sys_InitGame.py`
- **Source**: `engine/sys_dll2.cpp`, `HWND *pmainwindow`. Linux ELF name is `pmainwindow` (there is also `_GLOBAL__sub_I_pmainwindow`, ignored).

## Availability

- Same coverage as `Sys_InitGame`: all 11 engine configs, every declared platform.
- True mapped `.data` / `.bss` pointer object. Consumers read the global address, not a code-operand field.

## Predecessors

- Located in the same run as `Sys_InitGame`. No YAML `expected_input`.

## How it is located

After `Sys_InitGame` is anchored, the finder recovers the unique direct `GL_SetMode` / `GL_SetModeLegacy` call whose arg0 is a dereference of one writable global and whose arg1/arg2 are addresses of two other writable globals:

```
GL_SetMode(*pmainwindow, &maindc, &baseRC, ...)
```

arg0 is `*pmainwindow`: a register is loaded from the global, then `[reg]` is passed as the window handle. The `gv_sig` instruction is that load (the four-byte displacement names `pmainwindow`), not the subsequent dereference.

## Pitfalls

- The global has many other code xrefs (`Sys_VID_FlipScreen`, `EngineSurface::pushMakeCurrent`, `VGui_ViewportPaintBackground`, `Sys_Error`). String or unique-xref discovery is not viable.
- Dedicated-listen paths may skip the `pmainwindow = pwnd` store; the `GL_SetMode` load still names the same object.
- Do not take the HWND value (`*pmainwindow`) as the artifact address.
