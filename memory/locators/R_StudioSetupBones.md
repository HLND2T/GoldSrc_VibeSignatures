---
title: R_StudioSetupBones locator
type: note
permalink: goldsrc-vibesignatures/locators/r-studiosetupbones
tags:
  - locator
  - engine
  - func
---

# R_StudioSetupBones

## Symbol

- **Name**: `R_StudioSetupBones`
- **Category**: `func`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-R_StudioSetupBones.py`
  (via `preprocess_common_skill` + `func_xrefs`)

## Availability

- Declared in 10 configs: cof-5936, hl-10210, hl-3248, hl-3266, hl-3329, hl-3647,
  hl-4554, hl-6153, hl-8684, svencoop-10257.
- Platforms: Windows + Linux (no `platform:` gating).
- Inlined / absent: none observed; the bone-name comparison that anchors it belongs to the
  player gait blend, which every family keeps as a standalone routine.

## Predecessors

- None. `find-R_StudioSetupBones` has no `expected_input`; it is a root finder.

## How it is located

1. The finder declares a single `func_xrefs` entry for `R_StudioSetupBones` with
   `xref_strings: ["FULLMATCH:Bip01 Spine"]` — no GV, signature or function xrefs.
2. `FULLMATCH:` forces an exact whole-string C-string match; the shared xref resolver maps
   that literal to its owning function and requires a unique candidate.
3. The classic signature path is tried first (`preprocess_func_sig_via_mcp`); the string
   xref is the fallback when no prior artifact helps. `old_yaml_map=None`, so an old
   artifact signature can never be the discovery anchor.
4. Emits `func_name`/`func_sig`/`func_va`/`func_rva`/`func_size`.

## Pitfalls

- `"Bip01 Spine"` is a bone-name literal used by the player gait blend; it must be matched
  exactly (`FULLMATCH:`), never as a substring, or the anchor could drift to another
  skeleton-aware routine.
- This function is one of the three roles that must remain mutually distinct with
  `R_StudioSaveBones` and `R_StudioMergeBones`; its exclusion from the SaveBones candidate
  set is by exact `func_va` from this artifact, so a wrong anchor here corrupts the
  downstream SaveBones locator.
- Discovery never consumes an old artifact signature.

## Evidence

- `find-R_StudioSetupBones` is the DAG predecessor for `find-R_StudioSaveBones`
  (callee-role exclusion) and for `find-R_StudioRenderModel`
  (`exclude_callees`).
