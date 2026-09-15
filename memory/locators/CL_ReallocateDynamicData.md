---
title: CL_ReallocateDynamicData locator
type: note
permalink: goldsrc-vibesignatures/locators/cl-reallocatedynamicdata
tags:
  - locator
  - engine
  - func
---

# CL_ReallocateDynamicData

## Symbol

- **Name**: `CL_ReallocateDynamicData`
- **Category**: `func`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-CL_ReallocateDynamicData.py`

## Availability

- Declared in 10 engine configs: cof-5936, hl-10210, hl-3248, hl-3266, hl-3329, hl-3647,
  hl-4554, hl-6153, hl-8684, svencoop-10257.
- Platforms: no `platform:` gating; only hl-10210, hl-8684 and svencoop-10257 declare
  `module_linux: hw.so`, the other seven configs are Windows-only here.
- Inlined / absent: exists as a standalone entry in every build, but GCC also **inlines this
  allocator** into resource/serverinfo handling, so its diagnostic literal can appear inside
  other functions (see below).

## Predecessors

- None. `find-CL_ReallocateDynamicData` has no `expected_input` and passes `old_yaml_map=None`.
- It is the **required predecessor** for `find-CL_ReallocateDynamicData-decompiles`
  (which emits `cl_max_edicts`, `cl_entities`, `cl_frames`).

## How it is located

Pattern A string xref with an exclusion set, in `FUNC_XREFS`:

1. Positive: `xref_strings: ["FULLMATCH:CL_Reallocate cl_entities\n"]` — exact equality
   (`FULLMATCH:` prefix), so only functions containing that exact diagnostic qualify.
2. Exclusions: `exclude_strings: ["FULLMATCH:Setting up renderer...\n",
   "FULLMATCH:Serverinfo packet received.\n"]`. The docstring states GCC also inlines this
   allocator into resource/serverinfo handling, so the exclusion subtracts the functions
   containing those literals (the resource-registration and serverinfo hosts) instead of the
   real entry.
3. Exactly one candidate must remain; emit `func_name`, `func_sig`, `func_va`, `func_rva`,
   `func_size`.

## Pitfalls

- The exclusion set is not optional: without it the same diagnostic surfaced from inlined
  copies yields multiple candidates and the finder fails closed.
- Docstring contract: "Discovery never consumes an old artifact signature"
  (`old_yaml_map=None`).
- This function's body is the anchor for three GVs, not the GVs themselves. The frame-ring
  memset inside it owns the `cl_frames` array base; render-time accesses can encode an
  interior playerstate member address instead — see `cl_frames`.
- CoF (`cof-5936`) is Windows-only in this repo.
