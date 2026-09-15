---
title: V_CalcRefdef locator
type: note
permalink: goldsrc-vibesignatures/locators/v-calcrefdef
tags:
  - locator
  - client
  - func
---

# V_CalcRefdef

## Symbol

- **Name**: `V_CalcRefdef`
- **Category**: `func`
- **Module**: client (`client.dll` / `client.so`)
- **Producer**: `ida_preprocessor_scripts/find-client-private-predecessors.py`

## Availability

- Declared in 1 config: svencoop-10257.
- Platforms: Windows + Linux.
- Inlined / absent: none observed for Sven. The finder itself is registered in all 14 client configs, but it only materializes names the config lists in `expected_output` — V_CalcRefdef appears only in the Sven `client` module, so it is not produced for cof/CS/CZ/CZDS/HL.

## Predecessors

- None (ABI root).

## How it is located

1. Primary path: exactly one `idautils.Entries()` entry named `V_CalcRefdef` whose
   `ida_funcs.get_func(ea).start_ea == ea`. Sven's `client.so`/`client.dll` exports it
   (the reference IDB shows the `Exported entry` comment on the entry).
2. Fallback path (Windows-only, when the export table yields nothing for every target): the
   Metahook blob ABI recovery in `_client_blob_exports`. The original blob header must bind
   to the exact decrypted bytes and image base, and the straight-line initializer at
   `header.export_point` is decoded. `recover_client_export_table` proves one complete
   43-dword `cldll_func_t` stack table copied via `rep movsd` into the first cdecl argument;
   `V_CalcRefdef` is slot 19.
3. The resolved address must be executable and an exact function start (required only for
   slots 15/19/39); the finder validates an in-IDB signature and writes
   `func_name`/`func_va`/`func_rva`/`func_size`/`func_sig`.
4. This function then feeds `find-V_CalcRefdef-decompiles`, which recovers
   `g_bRenderingPortals_SCClient` from its body.

## Pitfalls

- `V_CalcRefdef` is present in the SDK `cldll_func_t` as slot 19; the slot number is the
  ABI identity but is never copied across binaries as an address.
- The finder is registered in every client config but `V_CalcRefdef` is an expected output
  only for svencoop-10257 — a missing output for other configs is expected, not a failure.
- Only the three consumed slots need exact current-IDB function starts; unrelated ABI
  callbacks may remain undefined in a fresh warm IDB.
