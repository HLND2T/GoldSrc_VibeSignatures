---
title: VideoMode_Create locator
type: note
permalink: goldsrc-vibesignatures/locators/videomode-create
tags:
  - locator
  - engine
  - func
---

# VideoMode_Create

## Symbol

- **Name**: `VideoMode_Create`
- **Category**: `func`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-VideoMode_Create.py`

## Availability

- Declared in all 10 engine configs: cof-5936, hl-10210, hl-3248, hl-3266, hl-3329, hl-3647, hl-4554, hl-6153, hl-8684, svencoop-10257.
- Platforms: Windows + Linux (no `platform:` gate in any config; the script itself is platform-agnostic). Linux artifacts exist for hl-10210, hl-8684 and svencoop-10257.
- Inlined / absent: always present. It is `void __cdecl VideoMode_Create()` and every build keeps it as a standalone entry; what is inlined *into* it varies (see pitfalls).

## Predecessors

- None. `find-VideoMode_Create` has no `expected_input`.

## How it is located

1. Single positive anchor: `xref_strings: ["FULLMATCH:-fullscreen"]` — exact C-string match on the fullscreen command-line literal, then the owning functions of its xrefs.
2. `xref_gvs`, `xref_signatures`, `xref_funcs` are empty and all `exclude_*` lists are empty, so the candidate set is exactly the set of `-fullscreen` owners.
3. Owner recovery runs, and the payload must yield exactly one candidate; ambiguity fails closed and nothing is written.
4. Emit `func_name`, `func_sig` (derived from the recovered body), `func_va`, `func_rva`, `func_size`. No LLM, no byte scan.
5. The other windowed-state literals (`-sw`, `-startwindowed`, `-windowed`, `-window`, `-full`) also live in this function and would work as anchors; `-fullscreen` is the one the finder pins because it is a validated single-owner anchor on every registered build.

## Pitfalls

- The shipped builds carry `EngineD3D` / `-d3d` / `-gl` handling that is absent from the local official-source revision. Machine code and DWARF are authoritative; the reference procedures carry the same warning.
- `VideoMode_Create` is not a thin wrapper: it allocates `operator new(0x1BCu)` and runs the inlined `CVideoMode_Common::CVideoMode_Common()` and `CVideoMode_OpenGL::CVideoMode_OpenGL(bool)` constructors, including the vftable swaps (`CVideoMode_Common_vftable` → `CVideoMode_OpenGL_vftable`) and the `SDL_GetDesktopDisplayMode` call. The `videomode` store sits after those inlines, so the function size is the whole construction sequence (hl-10210 win `0x1ad` / linux `0x1d5`; hl-8684 win `0x114` / linux `0x19e`; svencoop-10257 linux `0x1f7`).
- Because `videomode` is written inside this function and Windows builds have more than one legitimate access to that global, the `videomode` GV is recovered by an LLM over the *annotated reference* of this function rather than by a byte scan — see `VideoMode_Create-decompiles`. Keep this artifact's signature valid, since `find-VideoMode_Create-decompiles` and `find-CVideoMode_Common_PlayStartupSequence` both verify it by `_find_unique_bytes` before proceeding (a stale signature aborts both).
- Linux encoding differs: the store is `mov ds:videomode, esi` on Windows/one build but a different operand/displacement on the Linux PIC builds, so nothing about the store instruction may be hardcoded.
