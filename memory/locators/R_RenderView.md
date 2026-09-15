---
title: R_RenderView locator
type: note
permalink: goldsrc-vibesignatures/locators/r-renderview
tags:
  - locator
  - engine
  - func
---

# R_RenderView

## Symbol

- **Name**: `R_RenderView`
- **Category**: `func`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-R_RenderView.py`

## Availability

- Declared in 10 engine configs: cof-5936, hl-10210, hl-3248, hl-3266, hl-3329, hl-3647, hl-4554, hl-6153, hl-8684, svencoop-10257.
- Platforms: Windows + Linux where `hw.so` ships (hl-8684, hl-10210, svencoop-10257); the remaining seven configs are Windows binaries only.
- Inlined / absent: never inlined; `R_RenderScene` and the inlined `R_SetupFrame` live inside it, not the other way round. On Sven the exported entry is `R_RenderView_SvEngine(int viewIdx)` — a genuine argument difference, not a duplicate function, so no separate scanner is needed.

## Predecessors

- None. It is the DAG root for `find-S_ExtraUpdate`.

## How it is located

1. `xref_strings = ["R_RenderView: NULL worldmodel"]` is the anchor: the candidate set is every function that references that literal (substring match over the IDB's C-string list, resolving each string's data/code references to the owning function).
2. `preprocess_common_skill` intersects the string-derived candidate set with the (empty) set of other positive sources, applies `exclude_*` filters, and requires a unique surviving function.
3. Emits `func_name`/`func_sig`/`func_va`/`func_rva`/`func_size`. No byte signature participates in discovery.

## Pitfalls

- The string is matched as a *substring* (no `FULLMATCH:` prefix), so a similarly worded literal elsewhere would join the candidate set; uniqueness of the final function is the only gate.
- Unlike its sibling finders in this batch, this one forwards the caller's `old_yaml_map` into `preprocess_common_skill` rather than passing `None` — the shared skill uses it for the existing-artifact fast path, so a stale artifact can short-circuit re-discovery.
- Sven's entry takes an `int viewIdx` argument (Windows `0x1d537b0`, Linux `0x13ba80` per the Sven locator notes); consumers must not assume a void signature.
- `S_ExtraUpdate` is located from this artifact's callee set, so an incorrect `func_va` here silently corrupts the downstream symbol.
