---
title: Draw_FillRGBA locator
type: note
permalink: goldsrc-vibesignatures/locators/draw-fillrgba
tags:
  - locator
  - engine
  - func
---

# Draw_FillRGBA

## Symbol

- **Name**: `Draw_FillRGBA`
- **Category**: `func`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-renderer-draw-helpers.py`

## Availability

- Declared in 9 engine configs: cof-5936, hl-10210, hl-3248, hl-3266, hl-3329,
  hl-3647, hl-4554, hl-6153, hl-8684.
- Platforms: Windows + Linux (producer has no `platform` gating).
- Inlined / absent: not declared for svencoop-10257 — SvEngine has a **different
  `cl_enginefuncs` layout**, where slot 11 is not a function start, so the HL/CoF indices
  must not be reused there.

## Predecessors

- `cl_enginefuncs` — `gv_va` supplies the table base.
- `SCR_UpdateScreen_RenderBody` and `Sys_Error` — declared `expected_input` entry gate; the
  finder returns False if their `func_va` (or the table's `gv_va`) is missing.

## How it is located

1. Read `cl_enginefuncs`'s `gv_va` and compute the slot address
   `table + 11 * 4` (`cl_enginefunc_t` field order, `engine/APIProxy.h`).
2. Read the dword at that slot and require it to be a **function start**
   (`ida_funcs.get_func(ptr).start_ea == ptr`); otherwise report
   `Draw_FillRGBA_error = "slot is not a function start"` and write nothing.
3. Validate the blend-factor immediates in that body as an **output validator, not a
   discovery anchor**: the body must contain `GL_SRC_ALPHA` (0x302) and must **not** contain
   `GL_ONE_MINUS_SRC_ALPHA` (0x303). Slot 130 (`Draw_FillRGBABlend`) is the mirror case that
   contains both. A mismatch reports `"blend factor immediates do not match"`.
4. `_inspect_function_via_mcp` emits the function. If that fails (see pitfalls) the finder
   falls back to `CUSTOM_SIG`.

There is no string and no engine caller for this function, so the table slot is the only
deterministic anchor. Discovery never uses a byte pattern or an old YAML.

## Pitfalls

- `_inspect_function_via_mcp` auto-wildcards immediates, so `Draw_FillRGBA` and
  `Draw_FillRGBABlend` (byte-identical apart from `mov edx, 1` vs `mov edx, 303h`) can
  produce **no unique `func_sig`** and the normal write path fails. The fallback rebuilds
  the signature with immediates **pinned** and only relocatable operands
  (`o_mem` / `o_near` / `o_far` / `o_displ`) wildcarded, then binary-searches the shortest
  token prefix (minimum 6 tokens) that matches exactly once in the segment via
  `ida_bytes.find_bytes(..., radix=16)` using the string signature form. If even the pinned
  signature is not unique the symbol is skipped and `debug` prints
  `pinned signature failed (...)`.
- `ida_bytes.find_bytes` wildcard search returns `BADADDR` on the terminating probe;
  uniqueness is decided by "a second match appeared", so the last match must be kept in a
  separate variable.
- The slot index is only valid for the HL/CoF `cl_enginefunc_t` order, validated across
  hl-10210 / hl-8684 / hl-4554 / hl-6153 and cof-5936. Do not transfer these indices to
  SvEngine.
- The GL enum check is a validator, not a discriminator — if a build's body no longer
  mentions the blend factors the finder fails closed rather than falling back to a raw
  table read.
