---
title: GameStudioRenderer_vtable locator
type: note
permalink: goldsrc-vibesignatures/locators/gamestudiorenderer-vtable
tags:
  - locator
  - client
  - vtable
---

# GameStudioRenderer_vtable

## Symbol

- **Name**: `GameStudioRenderer_vtable`
- **Category**: `vtable` (class `GameStudioRenderer`)
- **Module**: client (`client.dll` / `client.so`)
- **Producer**: `ida_preprocessor_scripts/find-client-studio-interface.py`

## Availability

- Declared in 14 client configs: cstrike-3248/3647/4554/6153/8684/10210, czero-8684/10210,
  czeror-8684/10210, hl-8684/10210, cof-5936, svencoop-10257.
- Platforms: Windows + Linux only where the client module ships a Linux half — cstrike-10210,
  cstrike-6153, cstrike-8684, hl-10210, hl-8684, svencoop-10257. The other 8 configs
  (cof-5936, cstrike-3248/3647/4554, czero-8684/10210, czeror-8684/10210) declare only
  `module_windows: client.dll`, so those runs are Windows-only.
- Always present; only the entry count and the per-platform layout differ.

## Predecessors

- `HUD_GetStudioModelInterface.<platform>.yaml` (produced by `find-client-private-predecessors`),
  consumed via `expected_input`.

## How it is located

1. The finder first proves the renderer object: from the exported `HUD_GetStudioModelInterface`
   body it locates the returned `r_studio_interface_t` (`version == 1`, `+4`/`+8` executable),
   then takes the `[studio+4, studio+8]` thunks, intersects the writable-data addresses both
   thunks reference (the common `this`), and collects candidate vtables from the object's dword 0
   plus every xref to the object (constructor vptr store, direct store, register-propagated
   source).
2. A candidate table is accepted only if exactly one of its entries matches the DrawModel
   thunk's dispatch (`GameStudioRenderer_StudioDrawModel`'s index); see that symbol's locator
   for the full gate. On Linux, Itanium RTTI at `table-4` resolves destructor/base-table residue.
3. The emitted artifact is `vtable_class`/`vtable_symbol = GameStudioRenderer`,
   `vtable_va`/`vtable_rva`, `vtable_size = numvfunc * 4`, `vtable_numvfunc` and
   `vtable_entries` — a map of index → function address for consecutive executable dwords
   starting at `vtable_va`; the walk stops at the first dword that is not a function start.

## Pitfalls

- `vtable_va` is the pointer stored in the object, i.e. the **first function slot**. On
  Linux/Itanium the typeinfo pointer sits at `vtable_va - 4` and offset-to-top at `-8`; the
  finder reads `table-4` only to compare RTTI, and never emits a "group start". Do not add 8.
- Entry counts differ per ABI and per game family — hl-10210 25 win / 26 linux,
  cstrike-8684 28 / 29, svencoop-10257 30 / 32 — so `vtable_numvfunc` is discovered, never
  assumed, and the same class does not have the same index on both ABIs (DrawModel is 2 on
  Windows, 3 on Linux).
- This is the client renderer class vtable (`CStudioModelRenderer` / `CGameStudioModelRenderer`).
  It is unrelated to the engine's `r_studio_interface_t` version table found at `studio` in the
  same finder, even though both are reached from `HUD_GetStudioModelInterface`.
- Other finders (`find-GameStudioRenderer_StudioDrawModel-decompiles`,
  `find-GameStudioRenderer_StudioRenderModel-decompiles`,
  `find-GameStudioRenderer-inner-player`) consume `vtable_entries` to derive `vfunc_index` for
  their targets; changing this artifact's entry map changes their output.
