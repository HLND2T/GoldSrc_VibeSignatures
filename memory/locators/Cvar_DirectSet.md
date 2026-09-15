---
title: Cvar_DirectSet locator
type: note
permalink: goldsrc-vibesignatures/locators/cvar-directset
tags:
  - locator
  - engine
  - func
---

# Cvar_DirectSet

## Symbol

- **Name**: `Cvar_DirectSet`
- **Category**: `func`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-Cvar_DirectSet.py` (thin wrapper over
  `preprocess_common_skill`)

## Availability

- Declared in 10 configs: cof-5936, hl-10210, hl-3248, hl-3266, hl-3329, hl-3647, hl-4554,
  hl-6153, hl-8684, svencoop-10257.
- Platforms: Windows + Linux. Linux artifacts exist for hl-10210, hl-8684 and svencoop-10257;
  the other configs are Windows-only engine builds.
- Inlined / absent: none observed. `Cvar_DirectSet` is the anchor of the whole cvar family and is
  present in every covered engine binary.

## Predecessors

- None. It is the root of the cvar chain and feeds `find-Cvar_Set`, `find-cvar_hooks` and
  `find-Cvar_Set_to_Cvar_DirectSet_callsites` via `expected_input`.

## How it is located

1. `xref_strings: ["FULLMATCH:***PROTECTED***"]` — exact literal, not substring.
2. `_string_candidates` unions the owning functions of every matching string item;
   `preprocess_common_skill` intersects the positive sets (here a single set) and requires
   **exactly one** surviving function.
3. Emits `func_name` / `func_va` / `func_rva` / `func_size` / `func_sig`. The plain signature is
   tried first; if it cannot be resolved uniquely the finder re-runs the same discovery with
   `generate_yaml_desired_fields` extended by `func_sig_allow_across_function_boundary:true` and
   records that flag on the artifact.

## Pitfalls

- The literal is **not byte-unique**. hl-8684 and hl-6153 Windows `hw.dll` contain two exact
  `***PROTECTED***` items — the protected-cvar print pair (`***PROTECTED***` +
  `Server cvar "%s" = "%s"` and `***PROTECTED***` + `"%s" changed to "%s"`). The finder relies on
  the union of *referencing functions* collapsing to one candidate; a build where the two copies
  gained two distinct owners would fail closed (no artifact) instead of choosing one. Do not
  "fix" such a failure by picking the first match.
- Discovery never consults a byte signature or the old YAML; only the live IDB string list plus
  function ownership. An LLM/`found_gv` style guess is not used here.
- `func_sig_allow_across_function_boundary` is a *finder-level* desired field. Putting it in the
  config symbol does nothing, and a pre-seeded long `func_sig` in an old YAML does not help,
  because the flag is only honoured at signature-generation time.
- This artifact is the gate for three downstream finders. If it is missing, `find-Cvar_Set`
  loses its tiebreak (and can then reject a Linux build), and `find-cvar_hooks` /
  `find-Cvar_Set_to_Cvar_DirectSet_callsites` fail outright.
- Blob engines (`hl-3248`, `hl-3266`, `hl-3329`, `hl-3647`) are analyzed from the decrypted
  `hw.decrypt.dll`; IDA may show the function as `sub_XXXXXXXX`. Match by artifact `func_va`, not
  by display name.
