---
title: Mod_FindName locator
type: note
permalink: goldsrc-vibesignatures/locators/mod-findname
tags:
  - locator
  - engine
  - func
---

# Mod_FindName

## Symbol

- **Name**: `Mod_FindName`
- **Category**: `func`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-Mod_FindName.py`

## Availability

- Declared in 10 engine configs: cof-5936, hl-10210, hl-3248, hl-3266, hl-3329, hl-3647,
  hl-4554, hl-6153, hl-8684, svencoop-10257.
- Platforms: no `platform:` gating; only hl-10210, hl-8684 and svencoop-10257 declare
  `module_linux: hw.so`, the other seven configs are Windows-only here.
- Inlined / absent: always present as a standalone entry; no inlining observed.

## Predecessors

- None. `find-Mod_FindName` has no `expected_input` and passes `old_yaml_map=None`.
- It is the **required predecessor** for `find-Mod_FindName-decompiles`
  (emits `mod_known`, `mod_numknown`).

## How it is located

Pattern A string xref in `FUNC_XREFS`:

1. `xref_strings: ["FULLMATCH:Mod_FindName: NULL name"]` — exact equality. The docstring
   states the model-name lookup owns both the diagnostic and the known-model array
   traversal, so the literal is used inside the target function (not by a caller).
2. Exactly one candidate; emit `func_name`, `func_sig`, `func_va`, `func_rva`, `func_size`.

## Pitfalls

- Discovery never consumes an old artifact signature (`old_yaml_map=None`); a pre-existing
  `Mod_FindName` YAML is not a discovery input.
- The literal already contains `/`-free text and a colon; keep it `FULLMATCH` rather than
  relaxing to a substring, or the diagnostic prefix used elsewhere can pull in extra owners.
- The model registry (`mod_known`) and count (`mod_numknown`) are recovered from this body by
  the `-decompiles` consumer, not by this finder.
- CoF (`cof-5936`) is Windows-only in this repo.
