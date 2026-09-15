---
title: R_StudioCalcAttachments locator
type: note
permalink: goldsrc-vibesignatures/locators/r-studiocalcattachments
tags:
  - locator
  - engine
  - func
---

# R_StudioCalcAttachments

## Symbol

- **Name**: `R_StudioCalcAttachments`
- **Category**: `func`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-R_StudioCalcAttachments.py`
  (via `preprocess_common_skill` + `func_xrefs`)

## Availability

- Declared in 10 configs: cof-5936, hl-10210, hl-3248, hl-3266, hl-3329, hl-3647,
  hl-4554, hl-6153, hl-8684, svencoop-10257.
- Platforms: Windows + Linux (no `platform:` gating).
- Inlined / absent: **GCC inlines attachment calculation into both draw implementations**,
  so the standalone copy can be absent from the caller's CFG on Linux. The finder therefore
  excludes the inlining owners rather than requiring the call edge to exist.

## Predecessors

- `R_StudioDrawModel.{platform}.yaml` (produced by `find-R_StudioDrawModel` /
  `-svencoop`, consumed via `expected_input`). Used as an `exclude_funcs` entry, not as a
  code anchor.

## How it is located

1. The finder declares a single `func_xrefs` entry with
   `xref_strings: ["FULLMATCH:Too many attachments on %s\n"]` — the attachment-count
   diagnostic that belongs to this function. `FULLMATCH:` forces an exact whole-string
   match; the shared resolver maps it to the owning function and expects a unique candidate.
2. Exclusions guard against the inlining owners:
   - `exclude_funcs: ["R_StudioDrawModel"]` — the engine's top-level draw routine that
     inlines attachment calculation;
   - `exclude_strings: ["FULLMATCH:models/player/%s/%s.mdl"]` — the second draw owner
     (`R_StudioDrawPlayer`), identified by its own literal rather than by address, because
     the `R_StudioDrawModel` exclusion alone does not cover it.
3. Classic signature path first, literal xref as fallback; `old_yaml_map=None`, so no prior
   artifact signature drives discovery.
4. Emits `func_name`/`func_sig`/`func_va`/`func_rva`/`func_size`.

## Pitfalls

- Without the two exclusions the literal can be attributed to a draw wrapper that inlined
  the body; both exclusions are required.
- `"Too many attachments on %s\n"` carries a trailing newline — match it exactly.
- This function is a role-exclusion input for `find-R_StudioRenderModel`
  (`exclude_callees`) and `find-R_StudioSaveBones` (callee-role filter), so an anchor error
  here propagates downstream.
- Discovery never consumes an old artifact signature.

## Evidence

- The finder docstring states the reason for the exclusions verbatim: "GCC inlines
  attachment calculation into both draw implementations."
