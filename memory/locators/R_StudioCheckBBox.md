---
title: R_StudioCheckBBox locator
type: note
permalink: goldsrc-vibesignatures/locators/r-studiocheckbbox
tags:
  - locator
  - engine
  - func
---

# R_StudioCheckBBox

## Symbol

- **Name**: `R_StudioCheckBBox`
- **Category**: `func`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-R_StudioCheckBBox.py`

## Availability

- Declared in 10 configs: cof-5936, hl-10210, hl-3248, hl-3266, hl-3329, hl-3647,
  hl-4554, hl-6153, hl-8684, svencoop-10257.
- Platforms: Windows + Linux (no `platform:` gating). The finder tries **both** the HL and
  the SvEngine diagnostic strings, so one script covers every family.
- Inlined / absent: always present as a slot in `engine_studio_api_t`; it is a public
  Studio callback, not a private routine.

## Predecessors

- None. `find-R_StudioCheckBBox` has no `expected_input`; the engine studio API table is
  re-derived from the interface diagnostic each run.

## How it is located

1. For each diagnostic string in `(HL_STUDIO_STRING, SVC_STUDIO_STRING)` — the
   ClientDLL_CheckStudioInterface interface-mismatch wording, HL vs SvEngine — call the
   shared `locate_studio_slot(session, diagnostic, 21 * 4)`:
   - require exactly one exact `STRTYPE_C` match of the diagnostic;
   - collect its owning function(s) (`ClientDLL_CheckStudioInterface`; Linux may have two
     owners, both referencing the same table);
   - scan each owner for a writable-data candidate whose dword run validates as
     `engine_studio_api_t` (45 dwords inspected, at least 43 non-zero executable code
     pointers) — absolute operands on Windows/non-PIC Linux, GOT-anchored
     `lea reg,[ebx+disp32]` on SvEngine Linux;
   - require exactly one surviving table, then read slot **21** (offset `21*4 = 0x54`,
     `common/r_studioint.h`) and require its dword to be an exact IDA function start.
2. Only diagnostic strings that resolve successfully contribute a `slot_va`; the finder
   requires exactly **one distinct** `slot_va` across both attempts (a Windows binary only
   matches the HL wording, a SvEngine binary only the SvEngine wording, and neither may
   produce two different addresses).
3. Materialize through `_inspect_function_via_mcp` at that slot and emit
   `func_name`/`func_va`/`func_rva`/`func_size`/`func_sig` (no across-boundary fallback is
   requested here).

## Pitfalls

- The ABI slot number is fixed by `common/r_studioint.h`; it must not be re-derived per
  family or copied from another binary's numeric index.
- This symbol exists **solely as a CullBox anchor** — the finder's docstring says so. Its
  only downstream consumer is `find-R_StudioCheckBBox-decompiles`, which recovers
  `R_CullBox` from its body.
- A table that validates but whose slot 21 is not an exact function start is rejected
  outright (no autoanalysis rescue).
- Discovery never uses a byte signature or an old artifact signature.

## Evidence

- The same `locate_studio_slot` helper anchors the ABI accessor family
  (`studioapi_GetCurrentEntity` @0x18, `studioapi_StudioSetHeader` @0x8C,
  `studioapi_SetRenderModel` @0x90, `studioapi_SetChromeOrigin` @0x9C) and
  `studioapi_SetupPlayerModel` @0x7C.
