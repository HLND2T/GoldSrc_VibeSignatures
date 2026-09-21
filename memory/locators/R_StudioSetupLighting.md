---
title: R_StudioSetupLighting locator
type: note
permalink: goldsrc-vibesignatures/locators/r-studiosetuplighting
tags:
  - locator
  - engine
  - func
---

# R_StudioSetupLighting

## Symbol

- **Name**: `R_StudioSetupLighting`
- **Category**: `func` plus globals `r_ambientlight` (`gv`, int), `r_shadelight` (`gv`, float),
  `r_plightvec` (`gv`, vec3), `r_colormix` (`gv`, vec3)
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-R_StudioSetupLighting.py`
  (shared `ida_preprocessor_scripts._studio_setup_common.preprocess_studio_setup_lighting`)

## Availability

- Declared in 11 engine configs: hl-3248, hl-3266, hl-3329, hl-3647, hl-4554, hl-6153,
  hl-8684, hl-10210, cof-5936, svencoop-8948, svencoop-10257.
- Platforms: Windows + Linux (no `platform:` gating). The finder tries both HL and
  SvEngine ClientDLL_CheckStudioInterface diagnostics, so one script covers every family.
- Inlined / absent: never inlined — it is `engine_studio_api_t` slot 24 (`0x60`).

## Predecessors

- None. The engine studio API table is re-derived from the interface diagnostic each run.

## How it is located

1. For each diagnostic in `(HL_STUDIO_STRING, SVC_STUDIO_STRING)`, call
   `locate_studio_slot(..., 24 * 4)` and require exactly one distinct `slot_va`.
2. Materialize the function at that slot (`_inspect_function_via_mcp`, across-boundary
   fallback if the strict window is not unique).
3. Recover the four globals from the slot body with a current-IDB operand walk:
   - `r_ambientlight`: unique int store of `plighting->ambientlight` (`alight_t+0`).
   - `r_shadelight`: unique float store of the int-to-float conversion of
     `plighting->shadelight` (`alight_t+4`, `fild` / `movd`+`cvtdq2ps`).
   - `r_plightvec`: unique 12-byte consecutive float-store cluster whose sources are
     `*(alight_t+0x14 + {0,4,8})` — `alight_t.plightvec` is a `float *`, so the walker
     tracks the second-level pointer load (`reg_origin` `('load', 0x14)` feeds
     `('ptrload', 0x14, disp)`). Covers integer `mov`, x87 `fld`/`fst`, SSE
     `movss`, and SvEngine GOTOFF forms.
   - `r_colormix`: unique 12-byte consecutive float-store cluster after the first
     `AND …, 0xFF00` (`r_icolormix` packing), sourced from the **inline**
     `alight_t.color` (`+8/+0xC/+0x10`). Integer `A3` stores of that AND are ignored.
4. `plighting` is the unique incoming pointer used both as a disp-0 dword load and as a
   disp-4 integer-to-float source, including reloads from the same `[ebp+8]` / `[esp+N]`
   slot. `r_blightvec` / `r_icolormix` are not emitted.

## Pitfalls

- Slot 24 is the real `R_StudioSetupLighting`, not a wrapper.
- `r_plightvec` and `r_colormix` are both 12-byte float clusters. They are told apart by
  their source: `r_plightvec` reads through the `alight_t+0x14` pointer, `r_colormix`
  reads the inline `alight_t.color` at `+8/+0xC/+0x10` after the `AND 0xFF00` packing.
  Do **not** identify either by store order or by a single operand.
- `r_icolormix`'s int stores (`(int)(color[i] * 0xC0FF) & 0xFF00`) must not be collected.
  On old MSVC builds they follow a `call __ftol` that returns in `eax`; without clearing
  volatile load origins across `call`, a stale `('ptrload', …)` on `eax` misattributes
  those stores to `r_plightvec` and produces two candidate clusters.
- Do not sort globals by VA: `r_ambientlight` and `r_shadelight` are adjacent on some
  builds and far apart on others.
- SvEngine Linux stores are GOTOFF (`gv_pic_addend`).

## Cross-version evidence (`r_plightvec`)

Verified with owned `IdaMcpLifecycle` (`restored_strict`) on the binaries the configs
declare; SVN tags read their decrypted `hw.decrypt.dll`.

| Tag | Platform | `R_StudioSetupLighting` | `r_plightvec` | Copy form |
| --- | --- | --- | --- | --- |
| hl-3248 | windows | `0x1d8e480` | `0x2c202f0` | integer `mov` |
| hl-3266 | windows | `0x1d8e460` | `0x2c202f0` | integer `mov` |
| hl-3329 | windows | `0x1d8e340` | `0x2becc10` | integer `mov` |
| hl-3647 | windows | `0x1d8e4b0` | `0x2beba90` | integer `mov` |
| hl-4554 | windows | `0x1d9a3f0` | `0x2b95890` | integer `mov` |
| hl-6153 | windows | `0x1d83020` | `0x2bc64b0` | integer `mov` |
| hl-8684 | windows | `0x1d84990` | `0x2bc99b0` | integer `mov` |
| hl-8684 | linux | `0x12b190` | `0xf25954` | x87 `fld`/`fst` |
| hl-10210 | windows | `0x101f3470` | `0x10dc62e0` | SSE `movss` |
| hl-10210 | linux | `0xc80c0` | `0xf7d934` | x87 `fld`/`fst` |
| cof-5936 | windows | `0x1dbe853` | `0x2c0e570` | integer `mov` |
| svencoop-8948 | windows | `0x1d8f640` | `0x851eaec` | x87 `fld`/`fst` |
| svencoop-8948 | linux | `0xf0bd0` | `0xd3325c` | GOTOFF x87 |
| svencoop-10257 | windows | `0x1d90400` | `0x855ec74` | x87 `fld`/`fst` |
| svencoop-10257 | linux | `0xa20e0` | `0xce5c9c` | GOTOFF x87 |

Independent cross-check (hl-10210 windows): four functions read the candidate with
`mulss xmm0, r_plightvec(+8)` (`DotProduct(normal, r_plightvec)`), and the IDBs for
hl-10210 linux, hl-8684 linux, and svencoop-8948 linux already name the address
`r_plightvec`. Addresses are regression evidence for their exact inputs, not locators.
