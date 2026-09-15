---
title: Draw_FillRGBABlend locator
type: note
permalink: goldsrc-vibesignatures/locators/draw-fillrgbablend
tags:
  - locator
  - engine
  - func
---

# Draw_FillRGBABlend

## Symbol

- **Name**: `Draw_FillRGBABlend`
- **Category**: `func`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-renderer-draw-helpers.py`

## Availability

- Declared in 9 engine configs: cof-5936, hl-10210, hl-3248, hl-3266, hl-3329,
  hl-3647, hl-4554, hl-6153, hl-8684.
- Platforms: Windows + Linux (producer has no `platform` gating).
- Inlined / absent: not declared for svencoop-10257 — SvEngine's `cl_enginefuncs` layout
  differs and slot 130 is not usable there.

## Predecessors

- `cl_enginefuncs` — `gv_va` supplies the table base.
- `SCR_UpdateScreen_RenderBody` and `Sys_Error` — declared `expected_input` entry gate.

## How it is located

1. Slot address = `cl_enginefuncs.gv_va + 130 * 4` (`cl_enginefunc_t` field order,
   `engine/APIProxy.h`).
2. The dword at the slot must be a function start, otherwise
   `Draw_FillRGBABlend_error = "slot is not a function start"` and nothing is written.
3. Blend-factor validator (output check, not discovery anchor): the body must contain
   **both** `GL_SRC_ALPHA` (0x302) and `GL_ONE_MINUS_SRC_ALPHA` (0x303) — this is the
   distinction from `Draw_FillRGBA`, whose body has only `0x302`.
4. Emission via `_inspect_function_via_mcp`, with the `CUSTOM_SIG` pinned-immediate fallback
   when the default signature generator cannot separate it from `Draw_FillRGBA`.

`Draw_FillRGBABlend` has **no engine caller** and no diagnostic string, so the table slot is
the only deterministic anchor. No byte pattern or old YAML participates.

## Pitfalls

- The immediates matter: `_inspect_function_via_mcp` wildcards them, and this function
  differs from `Draw_FillRGBA` only by `mov edx, 303h` vs `mov edx, 1`. Expect the
  pinned-immediate fallback to be the path actually taken, not an exotic branch. The
  fallback keeps immediates fixed and wildcards only `o_mem` / `o_near` / `o_far` /
  `o_displ`, growing from a 6-token seed and checking uniqueness with the string-form
  `ida_bytes.find_bytes`; a non-unique prefix aborts the symbol (`no unique signature`).
- `ida_bytes.find_bytes` returns `BADADDR` on the terminating probe; keep the previous match
  in a separate variable when testing uniqueness.
- Without an engine caller there is no call-site cross-check: the slot read plus the
  `0x302`/`0x303` validator are the entire confidence story. Do not reuse the index on
  SvEngine.
- If the inspected body is not a function start the finder fails closed with `_error`; there
  is no second anchor.
