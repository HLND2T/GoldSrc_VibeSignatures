---
title: ClientPortalManager_ResetAll locator
type: note
permalink: goldsrc-vibesignatures/locators/clientportalmanager-resetall
tags:
  - locator
  - client
  - func
---

# ClientPortalManager_ResetAll

## Symbol

- **Name**: `ClientPortalManager_ResetAll`
- **Category**: `func`
- **Module**: client (`client.dll` / `client.so`)
- **Producer**: `ida_preprocessor_scripts/find-ClientPortalManager_ResetAll.py`

## Availability

- Declared in 1 config: svencoop-10257 (client module only).
- Platforms: Windows + Linux (no `platform:` gate; the predecessor artifact exists on both).
- Inlined / absent: standalone on both builds. It owns no diagnostic literal of its own, which is
  exactly why the MetaHookSv-era locator (a raw byte pattern, e.g.
  `C7 45 ?? FF FF FF FF A3 ... E8 ... 8B 0D` in the manager wrapper) cannot be reused here.

## Predecessors

- `ClientPortalManager_CreateInvisiblePortalTextures` (produced by
  `find-ClientPortalManager_CreateInvisiblePortalTextures`, consumed via `expected_input`).

## How it is located

1. The predecessor YAML is read from the run's `new_binary_dir` and its `func_name` must equal
   `ClientPortalManager_CreateInvisiblePortalTextures`; otherwise the finder returns False
   (fail closed, no artifact).
2. The finder then calls `preprocess_common_skill` with an empty `xref_strings` / `xref_gvs` /
   `xref_signatures` and a single `xref_funcs` entry:
   `xref_funcs = ["ClientPortalManager_CreateInvisiblePortalTextures"]`. The only structural gate is
   that the target function must be a **unique caller** of the verified creator; a second caller (or
   none) rejects the candidate.
3. ResetAll clears the manager (portal vector, texture maps, cached state) and recreates the shared
   invisible portal texture, so the unique-caller relation is semantic, not accidental: it is the
   only code path that both empties the vector and re-runs the creator.
4. Artifact fields: `func_name` / `func_va` / `func_rva` / `func_size` / `func_sig`.

## Pitfalls

- This is the one place in the portal family where the anchor is an **edge**, not a literal. Any
  duplicated call to the creator (e.g. a future build that also recreates the texture on map
  change) turns the walk ambiguous and the finder fails closed.
- ResetAll is reachable from several manager entry points (the research note counted 8 call sites on
  10257); that fan-in is on ResetAll itself and does not affect this finder, which counts callers of
  the *creator*, not of ResetAll.
- The predecessor step runs the creator finder first, so `ResetAll` cannot be produced independently;
  ordering in the config (`find-ClientPortalManager_CreateInvisiblePortalTextures` before
  `find-ClientPortalManager_ResetAll`) is load-bearing.
- Research addresses (W 0x1004DCE0 / L 0xf99a0) are validation evidence only.
