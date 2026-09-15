---
title: D_FillRect locator
type: note
permalink: goldsrc-vibesignatures/locators/d-fillrect
tags:
  - locator
  - engine
  - func
---

# D_FillRect

## Symbol

- **Name**: `D_FillRect`
- **Category**: `func`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-renderer-draw-helpers.py`

## Availability

- Declared in 9 engine configs: cof-5936, hl-10210, hl-3248, hl-3266, hl-3329,
  hl-3647, hl-4554, hl-6153, hl-8684.
- Platforms: Windows + Linux (the producer declares no `platform` gating).
- Inlined / absent: not declared for svencoop-10257. Anchor-shape differs on the HL25
  Windows outlier (hl-10210 `hw.dll`), which dropped the `Downloading %s` literal.
- `D_FillRect` is `engine/gl_screen.c D_FillRect`.

## Predecessors

- `SCR_UpdateScreen_RenderBody` — via `expected_input` (used directly by the depth-two
  HL25 fallback).
- `Sys_Error` and `cl_enginefuncs` — also declared as `expected_input` (entry gate; the
  `Sys_Error` VA is loaded and reported in `_debug`).
- All three artifacts must exist and carry `func_va` / `gv_va`, otherwise the finder
  returns False before any walk.

## How it is located

Primary path (literal present):

1. Collect every xref site to the C string `Downloading %s`.
2. For each reference site take its *unit* — the IDA function that owns it, or, when the
   site lives in code IDA never promoted, the terminator-bounded basic block recovered by
   `region_items` (walk back/forward over contiguous `is_code` heads, stopping at
   `retn`/`ret`/`jmp`/`int3` or at the previous/next IDA function boundary).
3. Collect the unit's `call` targets that are function start EAs. Keep a callee `f` only if:
   `f` has **no calls of its own** (zero-call leaf), it has 1 or 2 callers, and *every*
   caller is either the literal's owner unit or a direct callee of
   `SCR_UpdateScreen_RenderBody`.
4. Exactly one survivor becomes `D_FillRect`; otherwise the run logs
   `D_FillRect_candidates` and writes nothing.

Fallback path (HL25 Windows, hl-10210 `hw.dll`, which has no `Downloading %s` literal):

5. Walk `SCR_UpdateScreen_RenderBody`'s direct callees; keep the one whose caller set is
   exactly `{SCR}` (the only-called-by-SCR intermediate), then take that intermediate's
   callee which is called only by it and calls nothing itself. `D_FillRect` therefore sits
   two edges below `SCR_UpdateScreen_RenderBody` (SCR → intermediate → D_FillRect).

The located address is inspected for `func_va` / `func_rva` / `func_size` / `func_sig`
(with an across-function-boundary retry). Discovery never uses a byte pattern or an old
YAML.

## Pitfalls

- HL25 Windows is the documented outlier — on that build the literal does not exist and the
  depth-two shape is the only anchor. The two paths are mutually exclusive
  (`if not cand:`), so a build that has the literal never reaches the fallback.
- The zero-call + "≤2 callers, all in {literal owner} ∪ SCR-callees" gate is what
  disambiguates the real leaf from the many other zero-call leaves in the engine; widening
  either condition reintroduces candidates.
- The literal's owner may be un-promoted code. `region_items` bounds the search with the
  previous/next IDA function and terminates on the first branch/return mnemonic; when
  several un-promoted functions share one gap (old HL builds) that terminator-bounded
  block is the recovery unit, because `ida_funcs.get_func` and `_ensure_function_owner`
  both fail there.
- A unique candidate is mandatory: the finder returns a `_candidates` list and skips the
  write instead of emitting a guess.
