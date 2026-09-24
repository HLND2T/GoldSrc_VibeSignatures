---
title: studioapi_StudioSetRenderamt locator
type: note
permalink: goldsrc-vibesignatures/locators/studioapi-studiosetrenderamt
tags:
  - locator
  - engine
  - func
---

# studioapi_StudioSetRenderamt

## Symbol

- **Name**: `studioapi_StudioSetRenderamt`
- **Category**: `func`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-studioapi_StudioSetRenderamt.py` (shares `ida_preprocessor_scripts/_studio_player_model_common.py`)

## Availability

- Declared in all 11 engine configs: cof-5936, hl-10210, hl-3248, hl-3266, hl-3329, hl-3647, hl-4554, hl-6153, hl-8684, svencoop-8948, svencoop-10257.
- Platforms: Windows + Linux where `hw.so` ships (hl-8684, hl-10210, svencoop-8948, svencoop-10257); the remaining configs are Windows binaries only. The finder itself is not platform-gated.
- Inlined / absent: never inlined — the table holds a direct code pointer to it in every build. Present as a standalone accessor (`0x33`-`0x4A` bytes depending on build).
- Emits [[r_blend]] alongside the entry: the accessor is that global's sole writable-data store owner.

## Predecessors

- None. It is the DAG root of the `CL_FxBlend` chain.

## How it is located

1. Find the exact studio-interface diagnostic literal: `HL_STUDIO_STRING` (`"Couldn't get client .dll studio model rendering interface.  Version mismatch?\n"`) for GoldSrc/HL25/CoF, `SVC_STUDIO_STRING` (`"Couldn't get client library studio model rendering interface. Version mismatch?\n"`) for SvEngine. The finder tries each wording in turn.
2. The owning function(s) pass `&engine_studio_api` to the client studio interface. The table VA is recovered from the owner's instruction operands: an absolute 4-byte writable-data operand, or on SvEngine Linux the PIC `lea reg, [ebx + disp32]` form after the `call __x86.get_pc_thunk.*` / `add ebx, imm32` GOT anchor is resolved. Linux DWARF builds may name two string owners; both reference the same table, so the locator collapses on the unique table VA.
3. Validate the candidate as `engine_studio_api_t`: writable non-executable data with >= 43 non-zero executable code-pointer dwords (`TABLE_DWORDS = 45`). Observed code-pointer runs: 46 on the HL25 family, 47 on cof-5936 and svencoop-10257.
4. Read the fixed ABI slot `SLOT_OFFSET = 0xAC` (`common/r_studioint.h`, the CZero-era addition) and require the value to be an exact function start.
5. Gate the body with `SLOT_SHAPE_WRITE_ALLOW_READS` (`gv_names = ("r_blend",)`): the sole non-derived writable-data store target, reads unrestricted. The shape must ignore reads because the accessor reads `currententity` before the call and the x87 builds read `r_blend` back between its two stores. On the PIC builds it takes its second tier — `r_blend` is only address-taken there (see [[r_blend]]) — so it drops synthesized (`tracked base + displacement`) targets and falls back to the sole read that is not a synthesized base. Emit the entry and [[r_blend]] together, then `find-CL_FxBlend` consumes the entry for the sole-call walk.
6. Because the tiny accessor has no unique strict-window signature, the artifact normally carries `func_sig_allow_across_function_boundary: true` (the across-boundary window still starts at the same entry).

## Pitfalls

- Never discover this from a byte signature or a stored artifact signature; the slot number is the only structural fact.
- SvEngine Linux encodes the table through its PIC GOTOFF prologue exactly like the other slots — the absolute-operand scan alone will find nothing there.
- The table validation window is >= 43 code pointers, not "all 45 dwords non-zero": trailing slots are legitimately distinct across families.
- The accessor is one of the tiny studio accessors whose wildcarded body matches many functions; expect the across-boundary signature form.
- Do not reuse the read-free write shapes here. The accessor legitimately reads `currententity` (and, on x87 builds, `r_blend` itself), so `SLOT_SHAPE_WRITE`, `SLOT_SHAPE_WRITE_NO_GV` and `SLOT_SHAPE_WRITE_PAIR` all fail the gate; only the write side may be constrained.
- Do not mistake the `1/255` reciprocal for a second store target. It lives in `.rdata` on the builds checked so far, is read-only, and is shared with several other renderer functions.
- **`renderamt` can masquerade as a global.** The locator synthesizes `tracked_base + displacement` targets, so on the PIC builds `mov [eax+2FCh], edx` is resolved to `currententity + 0x2FC` because the intervening `mov eax,[eax]` carries no disp32 operand and leaves the tracked register stale. That address is in the huge `.bss` and passes `is_writable_data`, so it must be filtered as a *derived* target, not silently accepted.
