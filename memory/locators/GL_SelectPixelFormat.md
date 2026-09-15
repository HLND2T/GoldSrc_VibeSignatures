---
title: GL_SelectPixelFormat locator
type: note
permalink: goldsrc-vibesignatures/locators/gl-selectpixelformat
tags:
  - locator
  - engine
  - func
---

# GL_SelectPixelFormat

## Symbol

- **Name**: `GL_SelectPixelFormat`
- **Category**: `func`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-GL_SelectPixelFormat.py`

## Availability

- Declared in 8 engine configs: cof-5936, hl-3248, hl-3266, hl-3329, hl-3647, hl-4554, hl-6153, hl-8684. **Not declared on hl-10210 or svencoop-10257.**
- Platforms: Windows-only (`platform: windows` in every config that declares it).
- Inlined / absent: on HL25 (hl-10210) the selection is **inlined into `GL_SetMode`** — the literal's owner becomes `GL_SetMode` itself, so no standalone entry exists. SvEngine uses `wglChoosePixelFormatARB/EXT` + glew and never owns this literal.

## Predecessors

- None.

## How it is located

- Single exact-match string anchor: `FULLMATCH:ChoosePixelFormat failed` through `xref_strings`. On every legacy Windows build this MessageBox diagnostic has exactly one owner: the `engine/gl_vidnt.c bSetupPixelFormat` path.
- Emitted fields: `func_name`, `func_sig`, `func_va`, `func_rva`, `func_size`.
- Discovery is string-only: no byte signature and no old YAML is consulted.
- Downstream, this artifact is a preferred locator for `GL_SetMode_call_qwglCreateContext` (the context creation is the first non-import indirect call after the direct `GL_SelectPixelFormat` call).

## Pitfalls

- Because HL25 inlines the selection, do not register this finder on hl-10210: the literal still exists but is owned by `GL_SetMode`, which would produce an artifact for the wrong symbol. (hl-10210 is correspondingly the one config whose `find-GL_SetMode_call_qwglCreateContext` declares no `GL_SelectPixelFormat.{platform}.yaml` input.)
- The body reports both the `ChoosePixelFormat` and the `SetPixelFormat` failure diagnostics; the finder anchors only on the `ChoosePixelFormat` literal, so anchor on that exact text rather than a shared prefix.
