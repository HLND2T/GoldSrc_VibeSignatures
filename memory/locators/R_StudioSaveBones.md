---
title: R_StudioSaveBones locator
type: note
permalink: goldsrc-vibesignatures/locators/r-studiosavebones
tags:
  - locator
  - engine
  - func
---

# R_StudioSaveBones

## Symbol

- **Name**: `R_StudioSaveBones`
- **Category**: `func`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-R_StudioSaveBones.py`

## Availability

- Declared in 10 configs: cof-5936, hl-10210, hl-3248, hl-3266, hl-3329, hl-3647,
  hl-4554, hl-6153, hl-8684, svencoop-10257.
- Platforms: Windows + Linux (no `platform:` gating).
- Inlined / absent: `R_StudioSaveBones` copies each bone name and both transformation
  matrices; compilers can **inline the writer into the top-level DrawModel/DrawPlayer
  routines**, which is why those roles (and their aliases) are explicitly excluded rather
  than trusted.

## Predecessors

All eight are consumed via `expected_input`; each must carry its declared field:

- `cached_numbones.{platform}.yaml` (`gv_va`)
- `cached_bonename.{platform}.yaml` (`gv_va`)
- `R_StudioMergeBones.{platform}.yaml` (`func_va`) — exclusion
- `R_StudioDrawModel.{platform}.yaml` (`func_va`) — exclusion
- `R_StudioDrawPlayer.{platform}.yaml` (`func_va`) — exclusion
- `R_StudioDrawPlayerBody.{platform}.yaml` (`func_va`) — exclusion
- `R_StudioSetupBones.{platform}.yaml` (`func_va`) — callee-role exclusion
- `R_StudioCalcAttachments.{platform}.yaml` (`func_va`) — callee-role exclusion

## How it is located

Deterministic intersection locator (no LLM):

1. Load all eight predecessor artifacts and read `cached_numbones.gv_va`,
   `cached_bonename.gv_va`, the four excluded `func_va`s and the two callee `func_va`s.
   Abort if any artifact lacks its field.
2. Require both globals to live in a mapped, **non-executable** segment (a data address).
3. Compute `name_owners` = union over `offset in range(32)` of the owning function starts of
   every data reference at `cached_bonename + offset`. This is the key step: optimized
   `R_StudioSaveBones` may address the array as `name[0][31]` (pointer-31, reading the
   trailing NUL), so matching only the base label would miss it.
4. `candidates = owners(cached_numbones) ∩ name_owners` — functions referencing both
   globals.
5. Subtract the proven source roles: `difference_update` the four excluded `func_va`s
   (MergeBones, DrawModel, DrawPlayer, DrawPlayerBody — the roles that inline the writer or
   alias the body).
6. For each callee role (`R_StudioSetupBones`, `R_StudioCalcAttachments`), discard every
   function that calls it (the caller cannot be the standalone writer).
7. Require exactly **one** surviving candidate, else fail (`targets` length must be 1;
   ambiguity fails closed).
8. Materialize through `_inspect_function_via_mcp`; fall back to
   `allow_across_function_boundary=True` (emitting
   `func_sig_allow_across_function_boundary: true`) when the strict window is ambiguous.

## Pitfalls

- **The exact-`cached_bonename`-xref shortcut finds MergeBones but misses SaveBones** —
  see the pointer-31 trailing-NUL offset (`base+31`) handled by step 3. Any new locator that
  regresses to a bare base-label xref will silently name the reader.
- A verified exclusion can "disappear" during owner recovery if nearby direct-call
  candidates confuse backtracking; only exact executable function starts supplied by the
  current validated dependency artifacts may be used as exclusions — never infer an
  alternative exclusion entry. This is covered by a synthetic regression in the repo.
- Post-conditions enforced project-wide: `R_StudioSaveBones`, `R_StudioMergeBones` and
  `R_StudioSetupBones` must remain **distinct** functions in every engine peer.
- Everything is sourced from current artifacts plus a live IDA query; no byte signature or
  old YAML drives discovery.

## Evidence

- The finder's own docstring names the failure it exists to prevent: "exact cached_bonename
  xrefs find MergeBones but miss SaveBones".
