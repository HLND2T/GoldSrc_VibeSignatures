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

- Declared in 10 engine configs: cof-5936, hl-10210, hl-3248, hl-3266, hl-3329, hl-3647, hl-4554, hl-6153, hl-8684, svencoop-10257.
- Platforms: Windows + Linux where `hw.so` ships (hl-8684, hl-10210, svencoop-10257); the remaining seven configs are Windows binaries only. The finder itself is not platform-gated.
- Inlined / absent: never inlined — the table holds a direct code pointer to it in every build. Present as a standalone 52-byte accessor.

## Predecessors

- None. It is the DAG root of the `CL_FxBlend` chain.

## How it is located

1. Find the exact studio-interface diagnostic literal: `HL_STUDIO_STRING` (`"Couldn't get client .dll studio model rendering interface.  Version mismatch?\n"`) for GoldSrc/HL25/CoF, `SVC_STUDIO_STRING` (`"Couldn't get client library studio model rendering interface. Version mismatch?\n"`) for SvEngine. The finder tries each wording in turn.
2. The owning function(s) pass `&engine_studio_api` to the client studio interface. The table VA is recovered from the owner's instruction operands: an absolute 4-byte writable-data operand, or on SvEngine Linux the PIC `lea reg, [ebx + disp32]` form after the `call __x86.get_pc_thunk.*` / `add ebx, imm32` GOT anchor is resolved. Linux DWARF builds may name two string owners; both reference the same table, so the locator collapses on the unique table VA.
3. Validate the candidate as `engine_studio_api_t`: writable non-executable data with >= 43 non-zero executable code-pointer dwords (`TABLE_DWORDS = 45`). Observed code-pointer runs: 46 on the HL25 family, 47 on cof-5936 and svencoop-10257.
4. Read the fixed ABI slot `SLOT_OFFSET = 0xAC` (`common/r_studioint.h`, the CZero-era addition) and require the value to be an exact function start.
5. Emit only the function entry (`SLOT_SHAPE_SKIP_GVS`); the accessor's global accesses are intentionally not recovered, because `find-CL_FxBlend` only needs the entry.
6. Because the tiny accessor has no unique strict-window signature, the artifact normally carries `func_sig_allow_across_function_boundary: true` (the across-boundary window still starts at the same entry).

## Pitfalls

- Never discover this from a byte signature or a stored artifact signature; the slot number is the only structural fact.
- SvEngine Linux encodes the table through its PIC GOTOFF prologue exactly like the other slots — the absolute-operand scan alone will find nothing there.
- The table validation window is >= 43 code pointers, not "all 45 dwords non-zero": trailing slots are legitimately distinct across families.
- The accessor is one of the tiny studio accessors whose wildcarded body matches many functions; expect the across-boundary signature form.
