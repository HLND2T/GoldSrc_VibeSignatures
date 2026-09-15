---
title: CL_FxBlend locator
type: note
permalink: goldsrc-vibesignatures/locators/cl-fxblend
tags:
  - locator
  - engine
  - func
---

# CL_FxBlend

## Symbol

- **Name**: `CL_FxBlend`
- **Category**: `func`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-CL_FxBlend.py`

## Availability

- Declared in 10 engine configs: cof-5936, hl-10210, hl-3248, hl-3266, hl-3329, hl-3647, hl-4554, hl-6153, hl-8684, svencoop-10257.
- Platforms: Windows + Linux where `hw.so` ships (hl-8684, hl-10210, svencoop-10257); the remaining seven configs are Windows binaries only.
- Inlined / absent: always a standalone `cl_tent.c` function. Never inlined into `studioapi_StudioSetRenderamt` or its callers.

## Predecessors

- `studioapi_StudioSetRenderamt` (produced by `find-studioapi_StudioSetRenderamt`, consumed via `expected_input` and the `func_va` field).

## How it is located

1. Load the predecessor artifact; require `func_name == studioapi_StudioSetRenderamt` and `func_va >= image_base` (fails closed on a missing or malformed dependency).
2. Enumerate every `call` inside the predecessor body and resolve its direct target.
3. Drop `__x86.get_pc_thunk.<reg>` stubs — SvEngine Linux compiles the accessor PIC, and every such function opens with a `call` to a <= 4-byte stub that is not a source-level call. Any target whose function span is `<= 4` bytes is skipped.
4. Require **exactly one** surviving target ("sole-call contract"): the accessor only calls `CL_FxBlend`.
5. Verify the role of the callee independently: its body must reference the pulse de-sync constant `363.0` (`ent->curstate.number * 363.0`, `engine/cl_tent.c`). The constant is looked for in `.rdata`/`.rodata` through absolute/SSE/x87 operands *and* through the SvEngine Linux PIC form — the walk finds the callee's GOT anchor (`call pc_thunk` followed by `add reg, imm32`, `op.type == o_imm`) and rebases `[gotreg+disp32]` operands before reading the rodata blob. Both an f32 and an f64 read of the 8-byte blob are tested, with a `1e-4` tolerance. At least one hit is required.
6. Emit `func_name`/`func_sig`/`func_va`/`func_rva`/`func_size`; if the strict window fails, retry with `allow_across_function_boundary` and set `func_sig_allow_across_function_boundary`.

## Pitfalls

- The sole-call contract is the whole locator: if the thunk filter is removed or the stub threshold changes, SvEngine Linux reports "sole-call contract violated" with the pc-thunk in the target list.
- The `363.0` check is a fail-closed semantic gate, not a hint. A wrong callee (for example a CRT helper) must not be accepted just because the call graph looked right.
- The de-sync float may be reached only through the PIC GOTOFF form on SvEngine Linux; an absolute-only scan would reject a correct callee.
- Historical fallback (not used by the finder): on very old builds whose studio table has < 46 entries, the note records an LLM `found_call` route from the existing `R_DrawTEntitiesOnList` reference — no such build is currently registered.
