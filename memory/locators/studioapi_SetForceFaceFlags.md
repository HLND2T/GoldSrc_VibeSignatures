---
title: studioapi_SetForceFaceFlags locator
type: note
permalink: goldsrc-vibesignatures/locators/studioapi-setforcefaceflags
tags:
  - locator
  - engine
  - func
---

# studioapi_SetForceFaceFlags

## Symbol

- **Name**: `studioapi_SetForceFaceFlags`
- **Category**: `func`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-studioapi_SetForceFaceFlags.py`
  (shared `_studio_player_model_common.preprocess_studio_slot`,
  `SLOT_SHAPE_WRITE_NO_GV`)

## Availability

- Declared in the same 11 engine configs as the rest of the studioapi
  slot-accessor family (hl-3248, hl-3266, hl-3329, hl-3647, hl-4554, hl-6153,
  hl-8684, hl-10210, cof-5936, svencoop-8948, svencoop-10257), on every platform
  the tag ships.
- Inlined / absent: never inlined — `engine_studio_api_t` slot 0x88. Tiny body,
  so the artifact always carries `func_sig_allow_across_function_boundary`.
- One finder serves both engine families by trying `HL_STUDIO_STRING` then
  `SVC_STUDIO_STRING`.

## Predecessors

- None. Emits **only** its own `func` artifact; `g_ForcedFaceFlags` belongs to
  `studioapi_GetForceFaceFlags`.

## How it is located

1. Same root as `studioapi_GetForceFaceFlags`: the unique studio-interface
   diagnostic → owning function(s) → the unique `engine_studio_api` table.
2. Read fixed ABI slot `0x88`; it must be an exact function start, immediately
   after `GetForceFaceFlags` at 0x84 and before `StudioSetHeader` at 0x8C.
3. Structured-operand decode with the `SLOT_SHAPE_WRITE_NO_GV` gate: the body
   must contain exactly one writable-data store base and no read base. The
   accessor is `flags -> g_ForcedFaceFlags`, so that single store target is the
   global the Getter reads.
4. The shape is validated but no `gv` is emitted — there is no
   `SLOT_SHAPE_WRITE` call here precisely so the two finders cannot both claim
   `g_ForcedFaceFlags.{platform}.yaml`.

## Cross-version evidence (2026-09-24, production locator)

`slot 0x88` → store target, which equals the `g_ForcedFaceFlags` address in
`studioapi_GetForceFaceFlags`.

| tag | platform | slot 0x88 | store target |
| --- | --- | --- | --- |
| hl-3248 | windows | `0x1D92900` | `0x246E238` |
| hl-3266 | windows | `0x1D928E0` | `0x246E238` |
| hl-3329 | windows | `0x1D927C0` | `0x243B0E0` |
| hl-3647 | windows | `0x1D92930` | `0x2439F88` |
| hl-4554 | windows | `0x1D9E8B0` | `0x24242C8` |
| hl-6153 | windows | `0x1D868D0` | `0x23902E8` |
| hl-8684 | windows | `0x1D88250` | `0x2393808` |
| hl-8684 | linux | `0x129D60` | `0x322FE0` |
| hl-10210 | windows | `0x101F3D10` | `0x104EA094` |
| hl-10210 | linux | `0xC63A0` | `0x320FCC` |
| cof-5936 | windows | `0x1DC3B71` | `0x246A318` |
| svencoop-8948 | windows | `0x1D91D40` | `0x8DB39A4` |
| svencoop-8948 | linux | `0xEE920` | `0xD73E8C` |
| svencoop-10257 | windows | `0x1D92C90` | `0x8DF3B2C` |
| svencoop-10257 | linux | `0x9FE30` | `0xD268CC` |

## Pitfalls

- The identity of this function rests on three independent facts: the fixed ABI
  slot 0x88, the IDB's restored `engine_studio_api_t` name, and the write-only
  single-store shape whose target equals slot 0x84's read. Do not replace the
  shape gate with `SLOT_SHAPE_SKIP_GVS`; it would emit the slot function with no
  behavioural evidence.
- Frame-pointer shapes vary (`mov eax,[esp+arg]` on hl-3248..hl-4554 vs
  `push ebp/mov ebp,esp/mov eax,[ebp+arg]` on hl-10210 Windows, cof-5936); the
  shape gate works on writable refs, not on the prologue, so all forms pass.
