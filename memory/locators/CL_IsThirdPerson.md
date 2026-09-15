---
title: CL_IsThirdPerson locator
type: note
permalink: goldsrc-vibesignatures/locators/cl-isthirdperson
tags:
  - locator
  - client
  - func
---

# CL_IsThirdPerson

## Symbol

- **Name**: `CL_IsThirdPerson`
- **Category**: `func`
- **Module**: client (`client.dll` / `client.so`)
- **Producer**: `ida_preprocessor_scripts/find-client-private-predecessors.py`

## Availability

- Declared in 14 configs: cof-5936, cstrike-10210, cstrike-3248, cstrike-3647, cstrike-4554, cstrike-6153, cstrike-8684, czero-10210, czero-8684, czeror-10210, czeror-8684, hl-10210, hl-8684, svencoop-10257.
- Platforms: Windows + Linux.
- Inlined / absent: none observed. On Windows cstrike-3248/3647 it is reachable only through the Metahook blob ABI fallback.

## Predecessors

- None (ABI root).

## How it is located

1. Primary path: exactly one `idautils.Entries()` entry named `CL_IsThirdPerson` whose
   `ida_funcs.get_func(ea).start_ea == ea`.
2. Fallback path (Windows-only, when the export table yields nothing): Metahook blob ABI
   recovery. The original blob header is bound to the exact decrypted bytes and image base,
   the initializer at `header.export_point` is decoded with a straight-line decoder, and
   `recover_client_export_table` proves a single 43-dword `cldll_func_t` stack table copied
   via `rep movsd` into the first cdecl argument. `CL_IsThirdPerson` is slot 15.
3. The address must be executable and an exact function start (only the three consumed slots
   get this requirement); the finder then validates an in-IDB signature and writes
   `func_name`/`func_va`/`func_rva`/`func_size`/`func_sig`.
4. This function then feeds `find-CL_IsThirdPerson-decompiles`, which recovers `g_iUser1`
   and `g_iUser2` from its body.

## Pitfalls

- The `cldll_func_t` slot number is fixed by the SDK ABI (15 in `APIProxy.h`); do not
  renumber it per build. Slot numbers are the ABI identity, but reference addresses are not.
- Only the consumed slots (15/19/39) need exact current-IDB function starts; requiring all
  43 entries to be functions over-constrains discovery on a fresh warm IDB.
- Export entries are used only when `func.start_ea == ea`; an interior name match is
  rejected.
