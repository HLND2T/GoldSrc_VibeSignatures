---
title: HUD_GetStudioModelInterface locator
type: note
permalink: goldsrc-vibesignatures/locators/hud-getstudiomodelinterface
tags:
  - locator
  - client
  - func
---

# HUD_GetStudioModelInterface

## Symbol

- **Name**: `HUD_GetStudioModelInterface`
- **Category**: `func`
- **Module**: client (`client.dll` / `client.so`)
- **Producer**: `ida_preprocessor_scripts/find-client-private-predecessors.py`

## Availability

- Declared in 14 configs: cof-5936, cstrike-10210, cstrike-3248, cstrike-3647, cstrike-4554, cstrike-6153, cstrike-8684, czero-10210, czero-8684, czeror-10210, czeror-8684, hl-10210, hl-8684, svencoop-10257.
- Platforms: Windows + Linux.
- Inlined / absent: none observed. On Windows cstrike-3248/3647 it is reachable only through the Metahook blob ABI fallback (no PE export names).

## Predecessors

- None (ABI root).

## How it is located

1. Primary path: `idautils.Entries()` must contain exactly one entry named
   `HUD_GetStudioModelInterface` whose `ida_funcs.get_func(ea).start_ea == ea` (an exact
   export-table function start).
2. Fallback path (Windows only, when no target name produced any export entry): the
   original Metahook blob is bound byte-for-byte to the decrypted PE, the straight-line
   initializer at `header.export_point` is decoded, and `recover_client_export_table` proves
   one complete 43-dword `cldll_func_t` stack table copied via `rep movsd` into the first
   cdecl argument. `HUD_GetStudioModelInterface` is slot 39.
3. The resolved address must be a loaded executable address with an exact current-IDB
   function start (required only for this and the other two consumed slots), and only the
   names the config declares are materialized.
4. `_inspect_function_via_mcp` generates and validates an in-IDB signature; the finder
   writes `func_name`/`func_va`/`func_rva`/`func_size`/`func_sig`.

## Pitfalls

- This is an ABI root, not a private guess: the export entry or the verified blob ABI table
  is the only evidence. Never accept a same-named IDB symbol or an invented export.
- Warm autoanalysis may leave slot 39 undefined as a function; the blob fallback therefore
  requires exact function starts only for slots 15/19/39, not for all 43 entries.
- The blob header (`image_base`) and the decrypted bytes must match the current binary
  identity exactly, otherwise the fallback returns `{}` and the whole finder fails.
- Recorded addresses (e.g. blob initializer VAs) are binary evidence only and are never
  selectors.
