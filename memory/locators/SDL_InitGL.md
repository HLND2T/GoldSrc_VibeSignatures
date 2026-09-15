---
title: SDL_InitGL locator
type: note
permalink: goldsrc-vibesignatures/locators/sdl-initgl
tags:
  - locator
  - engine
  - func
---

# SDL_InitGL

## Symbol

- **Name**: `SDL_InitGL`
- **Category**: `func`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-SDL_InitGL.py`

## Availability

- Declared in 3 engine configs: hl-10210, hl-6153, hl-8684.
- Platforms: Windows + Linux (no `platform:` gate in any of the three configs).
- Inlined / absent: none observed on the SDL-era builds; the wrapper is absent from the pre-SDL/WON-era configs, which do not register it.

## Predecessors

- None.

## How it is located

- Single exact-match string anchor: `FULLMATCH:glAccum` through `xref_strings` — the GL procedure name with **no trailing newline**.
- Rationale: the function (`engine/qgl.c`, Linux debug name `QGL_Init`, MetaHook name `SDL_InitGL`) is the engine-private wrapper that bulk-resolves GL procedure addresses through `SDL_GL_GetProcAddress`; it resolves one procedure slot per exact name literal, so `glAccum` has exactly one owner.
- Emitted fields: `func_name`, `func_sig`, `func_va`, `func_rva`, `func_size`.
- Discovery is string-only; no byte signature or old artifact is consulted.

## Pitfalls

- The `glAccum\n` variant belongs to a **logging wrapper** and must never be used as the anchor. Since `FULLMATCH:` compares whole string items, the bare `glAccum` item is the correct one; a substring/prefix anchor would be ambiguous between the two items.
- The symbol is a MetaHook-facing name for the SDL-era GL resolver; the Linux debug name is `QGL_Init`. Do not assume the artifact's name matches the build's symbol table.
