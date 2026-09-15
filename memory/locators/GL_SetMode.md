---
title: GL_SetMode locator
type: note
permalink: goldsrc-vibesignatures/locators/gl-setmode
tags:
  - locator
  - engine
  - func
---

# GL_SetMode

## Symbol

- **Name**: `GL_SetMode`
- **Category**: `func`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-GL_SetMode.py`

## Availability

- Declared in 4 engine configs: hl-10210, hl-6153, hl-8684, svencoop-10257.
- Platforms: Windows + Linux (no `platform:` gate in any of the four configs).
- Inlined / absent: on HL25 (hl-10210) this entry additionally **contains the inlined legacy pixel-format selection** that older builds kept in `GL_SelectPixelFormat`; that is why hl-10210 registers `GL_SetMode` but no `GL_SelectPixelFormat`. The pre-SDL builds use `GL_SetModeLegacy` instead and do not declare `GL_SetMode` at all.

## Predecessors

- None.

## How it is located

- Two string specs tried in order, each with `xref_strings` and the `FULLMATCH:` exact-text prefix; the first spec yielding a single-owner match wins:
  1. `FULLMATCH:Error initializing MSAA frame buffer\n` — the non-SvEngine MSAA framebuffer initialization failure reported from `GL_SetMode` (engine/vid_common.cpp).
  2. `FULLMATCH:GL_SetMode::glewInit() err = %i\n` — the SvEngine GLEW bootstrap diagnostic used instead.
- Emitted fields: `func_name`, `func_sig`, `func_va`, `func_rva`, `func_size`.
- Discovery is string-only; no byte signature or old artifact is consulted.
- This artifact is the host input for `find-GL_SetMode_call_qwglCreateContext` on the SDL-era builds (hl-10210, hl-6153, hl-8684), where the GL context is created inside this body.

## Pitfalls

- The two diagnostics are family-exclusive; the ordered waterfall exists because spec 1 has no match on SvEngine. If a build ever printed both, spec 1 would win.
- `%i` in the SvEngine literal is a format placeholder, not a literal byte — use the `FULLMATCH:` exact text including the `\n`.
- HL25 inlining means the body here is larger than the legacy `GL_SetModeLegacy`; do not assume a fixed size or a shared prologue with the legacy wrapper.
