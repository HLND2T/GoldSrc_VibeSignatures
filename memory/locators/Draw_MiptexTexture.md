---
title: Draw_MiptexTexture locator
type: note
permalink: goldsrc-vibesignatures/locators/draw-miptextexture
tags:
  - locator
  - engine
  - func
---

# Draw_MiptexTexture

## Symbol

- **Name**: `Draw_MiptexTexture`
- **Category**: `func`
- **Module**: engine (`hw.so` — hl-10210 Linux branch)
- **Producer**: `ida_preprocessor_scripts/find-Draw_MiptexTexture.py`

## Availability

- Declared in 1 config: hl-10210.
- Platforms: Linux-only. The finder is registered `platform: linux` and the hl-10210 symbol
  list declares `Draw_MiptexTexture` `platform: linux`.
- Inlined / absent: not covered on Windows (there `GL_LoadTexture2` is located directly by
  `find-GL_LoadTexture2`, `platform: windows`) and not declared for any other gamever.

## Predecessors

- None. `find-Draw_MiptexTexture` declares no `expected_input`.
- It is the predecessor of `find-Draw_MiptexTexture-decompiles` (`platform: linux`,
  hl-10210), which mines this body to recover `GL_LoadTexture2` (owned by the renderer-GL
  batch).

## How it is located

1. `preprocess_common_skill` with one `func_xrefs` entry:
   `FULLMATCH:Draw_MiptexTexture: Bad cached wad %s\n` — exact C-string equality, validated
   on every branch to have exactly **one** owner.
2. Referencing functions are collected through `_functions_referencing` →
   `_ensure_function_owner`, which backtracks a direct-call entry when IDA never promoted the
   owner. A `FULLMATCH` literal with no recoverable owner fails closed rather than silently
   matching elsewhere.
3. Exactly one candidate must survive; otherwise the finder returns None and writes nothing.
   `xref_gvs` / `xref_signatures` / `xref_funcs` are empty, so the literal is the sole anchor.
4. Fields written: `func_name`, `func_sig`, `func_va`, `func_rva`, `func_size` (no
   `func_sig_allow_across_function_boundary` is requested for this symbol).

## Pitfalls

- The diagnostic is Windows-absent on this branch; the Windows route for the downstream
  `GL_LoadTexture2` is `find-GL_LoadTexture2` (`platform: windows`), which takes over on the
  hl-10210 Windows artifact. Do not expect `Draw_MiptexTexture` there.
- `engine/gl_draw.c Draw_MiptexTexture` uploads a cached wad miptex through the full
  nine-argument `GL_LoadTexture2`, but the same body also contains a specialized upload entry.
  The downstream `-decompiles` step depends on the annotated reference pinning the
  nine-argument call site; that distinction is what the reference YAML is for, not this
  finder.
- A stale or polluted shared IDB string list can hide the literal (see the string-list
  pollution note); `preprocess_common_skill` re-arms the string list per run for that reason.
- Single-owner requirement: a build that inlines the loader changes the owner set and the
  finder fails closed instead of guessing.
