---
title: GL_SetModeLegacy locator
type: note
permalink: goldsrc-vibesignatures/locators/gl-setmodelegacy
tags:
  - locator
  - engine
  - func
---

# GL_SetModeLegacy

## Symbol

- **Name**: `GL_SetModeLegacy`
- **Category**: `func`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-GL_SetModeLegacy.py`

## Availability

- Declared in 6 engine configs: cof-5936, hl-3248, hl-3266, hl-3329, hl-3647, hl-4554.
- Platforms: Windows + Linux (no `platform:` gate in any of the six configs).
- Inlined / absent: this is the **pre-SDL / WON-era** `engine/vid_common.cpp GL_SetMode` body; the SDL-era builds (hl-10210, hl-6153, hl-8684, svencoop-10257) do not declare it and use `GL_SetMode` instead.

## Predecessors

- None.

## How it is located

- Single exact-match string anchor: `FULLMATCH:Error initializing gl driver, check that the GL driver file opengl32.dll exists` through `xref_strings`. The legacy build aborts GL mode selection when the `opengl32.dll` driver cannot be loaded, and this diagnostic has exactly one owner — `GL_SetModeLegacy` — on every validated legacy branch.
- Emitted fields: `func_name`, `func_sig`, `func_va`, `func_rva`, `func_size`.
- Discovery is string-only; no byte signature or old artifact is consulted.
- This artifact is the host input for `find-GL_SetMode_call_qwglCreateContext` on the legacy builds (its `HOST_FUNC_NAMES` order tries `GL_SetModeLegacy` before `GL_SetMode`).

## Pitfalls

- The symbol name is a repo-side label, not a build-side name — the underlying function is the legacy `GL_SetMode`. Keep the host selection in `find-GL_SetMode_call_qwglCreateContext` in mind: on the legacy builds the patched context-creation call lives in this body.
- The literal mentions `opengl32.dll` explicitly; the SvEngine/SDL families never print it, so this anchor is never valid there.
