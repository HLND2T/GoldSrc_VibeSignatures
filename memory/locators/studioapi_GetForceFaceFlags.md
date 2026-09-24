---
title: studioapi_GetForceFaceFlags locator
type: note
permalink: goldsrc-vibesignatures/locators/studioapi-getforcefaceflags
tags:
  - locator
  - engine
  - func
  - gv
---

# studioapi_GetForceFaceFlags

## Symbol

- **Name**: `studioapi_GetForceFaceFlags`
- **Category**: `func`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-studioapi_GetForceFaceFlags.py`
  (shared `_studio_player_model_common.preprocess_studio_slot`, `SLOT_SHAPE_READ`)
- Also produces the `g_ForcedFaceFlags` **gv** artifact.

## Availability

- Declared in 11 engine configs: hl-3248, hl-3266, hl-3329, hl-3647, hl-4554,
  hl-6153, hl-8684, hl-10210, cof-5936, svencoop-8948, svencoop-10257 — the same
  set that declares the rest of the studioapi slot-accessor family.
- Platforms: Windows + Linux (Linux only where the tag ships it).
- Inlined / absent: never inlined — it is `engine_studio_api_t` slot 0x84. The
  body is a 6-byte stub, so the artifact always carries
  `func_sig_allow_across_function_boundary`.
- One finder serves both engine families by trying `HL_STUDIO_STRING` then
  `SVC_STUDIO_STRING`; there is deliberately no `-svencoop` variant script.

## Predecessors

- None. Produces the accessor `func` artifact plus the `g_ForcedFaceFlags` `gv`
  artifact; `studioapi_SetForceFaceFlags` reads the shape of the sibling slot and
  emits only its own function.

## How it is located

1. The unique `ClientDLL_CheckStudioInterface` interface-mismatch diagnostic →
   owning function(s) → the unique `engine_studio_api` table
   (`validate_table_run`: writable data, `.data`, 45 code-pointer dwords).
2. Read fixed ABI slot `0x84`; it must be an exact function start. The IDB's
   restored `engine_studio_api_t` names the neighbourhood
   `0x80 StudioClientEvents / 0x84 GetForceFaceFlags / 0x88 SetForceFaceFlags /
   0x8C StudioSetHeader / 0x90 SetRenderModel` on hl-10210 and hl-8684 `hw.so`,
   which is why these two slots are unambiguous despite tiny bodies.
3. Structured-operand decode of the accessory body. The source returns the
   `static int g_ForcedFaceFlags`, so the shape gate `SLOT_SHAPE_READ` requires
   exactly one writable-data read base and zero write bases.
4. The `gv` artifact reuses the accessor's `func_sig` with
   `gv_inst_offset/length/disp` pointing at that load; SvEngine Linux is the
   eax-anchored GOTOFF form and additionally carries `gv_pic_addend`.
5. Role cross-check: the sibling slot 0x88 accessor stores the *same* address
   (see `studioapi_SetForceFaceFlags`), and SvEngine Linux names the ELF symbol
   `_ZL17g_ForcedFaceFlags` — the file-static spelling of engine source's
   `g_ForcedFaceFlags`.

## Cross-version evidence (2026-09-24, production locator)

Table is `.data` with `code_run 45` on every row; `slot` → `g_ForcedFaceFlags`.

| tag | platform | table | slot 0x84 | `g_ForcedFaceFlags` | `gv_pic_addend` |
| --- | --- | --- | --- | --- | --- |
| hl-3248 | windows | `0x1ED3520` | `0x1D928F0` | `0x246E238` | — |
| hl-3266 | windows | `0x1ED3520` | `0x1D928D0` | `0x246E238` | — |
| hl-3329 | windows | `0x1EA50B8` | `0x1D927B0` | `0x243B0E0` | — |
| hl-3647 | windows | `0x1EA41E0` | `0x1D92920` | `0x2439F88` | — |
| hl-4554 | windows | `0x1E829B8` | `0x1D9E8A0` | `0x24242C8` | — |
| hl-6153 | windows | `0x1E502F0` | `0x1D868C0` | `0x23902E8` | — |
| hl-8684 | windows | `0x1E53248` | `0x1D88240` | `0x2393808` | — |
| hl-8684 | linux | `0x2D6720` | `0x129D50` | `0x322FE0` | — |
| hl-10210 | windows | `0x1031C1E0` | `0x101F3D00` | `0x104EA094` | — |
| hl-10210 | linux | `0x2BD3C0` | `0xC6390` | `0x320FCC` | — |
| cof-5936 | windows | `0x1EC5B38` | `0x1DC3B67` | `0x246A318` | — |
| svencoop-8948 | windows | `0x1EDA960` | `0x1D91D30` | `0x8DB39A4` | — |
| svencoop-8948 | linux | `0x33CE20` | `0xEE900` | `0xD73E8C` | `0x33A000` |
| svencoop-10257 | windows | `0x1EE2898` | `0x1D92C80` | `0x8DF3B2C` | — |
| svencoop-10257 | linux | `0x2EF840` | `0x9FE10` | `0xD268CC` | `0x2EE000` |

## Pitfalls

- Do not confuse slot 0x84 with 0x88: both touch `g_ForcedFaceFlags`, but only
  0x84 reads it and only 0x88 stores it. `SLOT_SHAPE_READ` vs
  `SLOT_SHAPE_WRITE_NO_GV` keeps them apart.
- Do not select the `gv` anchor from the Setter as well — two finders writing
  `g_ForcedFaceFlags.{platform}.yaml` is a duplicate-output config error.
- cof-5936's accessors sit at odd function starts (`0x1DC3B67` / `0x1DC3B71`);
  that is the real IDA function boundary, not a misdecode.
- A GOTOFF site embeds var-GOT with no relocation: the runtime dword must be
  rebased by the GOT RVA (`gv_pic_addend`), otherwise the resolved address is
  wrong even though the signature is unique.
