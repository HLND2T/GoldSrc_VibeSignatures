---
title: Draw_Pic locator
type: note
permalink: goldsrc-vibesignatures/locators/draw-pic
tags:
  - locator
  - engine
  - func
---

# Draw_Pic

## Symbol

- **Name**: `Draw_Pic`
- **Category**: `func`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-renderer-draw-helpers.py` (HL/CoF, both
  platforms), `ida_preprocessor_scripts/find-renderer-draw-helpers-svencoop.py`
  (svencoop-10257, `platform: windows`)

## Availability

- Declared in 10 engine configs: cof-5936, hl-10210, hl-3248, hl-3266, hl-3329,
  hl-3647, hl-4554, hl-6153, hl-8684, svencoop-10257.
- Platforms: Windows + Linux on the 9 HL/CoF configs; **Windows-only on svencoop-10257**
  (the svencoop finder is `platform: windows` and the svencoop symbol list declares
  `Draw_Pic` `platform: windows`).
- Inlined / absent: on SvEngine Linux `Draw_Pic` is inlined into `SPR_Draw*`, so no
  standalone entry exists there. `Draw_Pic` is `engine/gl_draw.c Draw_Pic`.

## Predecessors

- `SCR_UpdateScreen_RenderBody` — required by both producers (the HL/CoF fallback walks its
  callees; the svencoop producer's only input).
- `Sys_Error` and `cl_enginefuncs` — additionally declared `expected_input` for the HL/CoF
  producer; all of `func_va` / `gv_va` must be present or the finder returns False before
  walking.

## How it is located

Primary path (HL/CoF, literal present):

1. Collect every xref site to `Draw_TransPic: bad coordinates`.
2. For each reference site, take its unit — the owning IDA function, or the
   **terminator-bounded basic block** when IDA never promoted the owner (`region_items`:
   walk back/forward over contiguous `is_code` heads, bounded by the previous/next IDA
   function and stopping at `retn`/`ret`/`jmp`/`int3`). The old-HL `Draw_TransPic` case is
   exactly why this block-bounded rule exists: `ida_funcs.get_func` and the shared
   `_ensure_function_owner` both failed there, and several un-promoted functions can share a
   single gap.
3. Take the unit's `call` / `jmp` targets that are function starts, and subtract
   `Sys_Error` — the bad-coordinates path calls `Draw_Pic` and `Sys_Error`.
4. Exactly one survivor becomes `Draw_Pic`; otherwise the run reports
   `Draw_Pic_candidates` and writes nothing.

Fallback path (HL25 Windows dropped the literal; SvEngine never had it):

5. For each callee `c` of `SCR_UpdateScreen_RenderBody` with exactly 2 callers, look at the
   callers other than SCR; if one of them is a wrapper whose only call target is `c` and
   which itself has a single caller, then `c` is `Draw_Pic`. `engine/gl_draw.c Draw_TransPic`
   is that wrapper.
   The svencoop producer uses *only* this shape, with an extra `len(calls(c)) <= 2` guard,
   and requires exactly one hit.

Emission: `_inspect_function_via_mcp` → `func_va` / `func_rva` / `func_size` / `func_sig`,
with an `allow_across_function_boundary` retry. No byte pattern or old YAML participates.

## Pitfalls

- HL25 Windows (`hw.dll`) is the outlier that dropped `Draw_TransPic: bad coordinates`; the
  same build keeps it on Linux, so a Linux/Windows result difference is expected, not a
  bug.
- SvEngine cannot use the literal at all (its `SPR_Draw*` diagnostics have different
  wording), and its `cl_enginefuncs` layout differs — the wrapper shape is the only route
  there.
- The wrapper condition is strict on purpose (single-caller wrapper, single callee, callee
  with exactly two callers). Relaxing any one of them pulls in unrelated delegation chains.
- Orphan literal owners are the norm on old builds, not an edge case.
