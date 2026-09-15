---
title: studioapi_SetChromeOrigin locator
type: note
permalink: goldsrc-vibesignatures/locators/studioapi-setchromeorigin
tags:
  - locator
  - engine
  - func
---

# studioapi_SetChromeOrigin

## Symbol

- **Name**: `studioapi_SetChromeOrigin`
- **Category**: `func`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-studioapi_SetChromeOrigin.py`,
  `ida_preprocessor_scripts/find-studioapi_SetChromeOrigin-svencoop.py`
  (shared `_studio_player_model_common.preprocess_studio_slot`, `SLOT_SHAPE_COPY12`)

## Availability

- Declared in 10 engine configs: hl-3248, hl-3266, hl-3329, hl-3647, hl-4554, hl-6153,
  hl-8684, hl-10210, cof-5936 (generic), svencoop-10257 (`-svencoop`).
- Platforms: Windows + Linux.
- Inlined / absent: never inlined — `engine_studio_api_t` slot 0x9C. Tiny body, so the
  artifact always carries `func_sig_allow_across_function_boundary`.

## Predecessors

- None. Produces the accessor plus *both* `r_origin` and `g_ChromeOrigin` GV artifacts.

## How it is located

1. Unique studio-interface diagnostic → owning function(s) → unique `engine_studio_api`
   table.
2. Read ABI slot `SLOT_OFF = 0x9C`; must be a function start.
3. Structured-operand decode. The source is `VectorCopy(r_origin, g_ChromeOrigin)`, i.e. a
   12-byte read cluster and a 12-byte write cluster. `cluster_bases` groups refs whose
   addresses are within 8 bytes of each other, so each vector collapses to one base.
4. Shape gate `SLOT_SHAPE_COPY12`: exactly one read base and one write base, and they must
   differ. Read base = `r_origin`, write base = `g_ChromeOrigin`.
5. Emit the accessor `func` artifact plus two `gv` artifacts, each anchored at the first
   base-referencing instruction of its cluster.

## Pitfalls

- Both globals come from **one** finder/owner, so the two GVs must be emitted together — a
  single-target locator cannot split them.
- The copy is encoded several ways across the family and all must be accepted: `mov` pairs,
  SSE `movss` (hl-10210), x87 `fld/fstp` (SvEngine), and eax-anchored GOTOFF PIC (SvEngine
  Linux). Direction is derived from the mnemonic, with `lea` counted as a read.
- A 12-byte cluster is three dwords; `cluster_bases` folds them so the artifact records
  exactly one base per side rather than three.
- Reference counts: `r_origin` ~20-25 functions, `g_ChromeOrigin` 3-4.
- SvEngine Linux: `r_origin` comes from the GOTOFF `lea` cluster base and `g_ChromeOrigin`
  from the `movss` store cluster base; both sites carry `gv_pic_addend`.
