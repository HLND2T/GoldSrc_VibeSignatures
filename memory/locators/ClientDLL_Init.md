---
title: ClientDLL_Init locator
type: note
permalink: goldsrc-vibesignatures/locators/clientdll-init
tags:
  - locator
  - engine
  - func
---

# ClientDLL_Init

## Symbol

- **Name**: `ClientDLL_Init`
- **Category**: `func`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-ClientDLL_Init.py` (thin wrapper over
  `preprocess_common_skill`)

## Availability

- Declared in 10 configs: cof-5936, hl-10210, hl-3248, hl-3266, hl-3329, hl-3647, hl-4554,
  hl-6153, hl-8684, svencoop-10257.
- Platforms: Windows + Linux (the cof/older-hl configs are Windows-only; hl-10210, hl-8684 and
  svencoop-10257 build both).
- Inlined / absent: the entry point itself always exists. What differs is its **body**: the
  compact builds in the repo are unusually large because HL25 inlines `LoadSecureClient`,
  `LoadInsecureClient`, `ClientDLL_Shutdown` and `ClientDLL_ClientMoveInit` into it, while public
  `LoadSecureClient` is stubbed to return false and this binary still calls `NLoadBlobFile`.

## Predecessors

- None. `find-ClientDLL_Init` has no `expected_input`.
- It feeds four consumers via `expected_input`: `find-ClientDLL_Shutdown`,
  `find-FreeBlob` (inlined-Shutdown form), `find-ClientDLL_HudInit-decompiles` and
  `find-ClientDLL_Init-pic-enginefuncs`.

## How it is located

1. `xref_strings: ["FULLMATCH:ScreenShake"]` — exact match on the literal passed to
   `HookServerMsg("ScreenShake", ...)` *inside* `ClientDLL_Init`.
2. The xref is mapped to its **owning function** through the shared `_ensure_function_owner`
   recovery, not treated as a function start (see Pitfalls).
3. `preprocess_common_skill` intersects the positive sets and requires exactly one surviving
   function.
4. Emits `func_name` / `func_va` / `func_rva` / `func_size` / `func_sig`. If the plain
   signature does not resolve uniquely, the finder retries with
   `generate_yaml_desired_fields` carrying `func_sig_allow_across_function_boundary:true`
   (raises the signature caps from 24/64 to 256/256) and records that flag in the YAML.

## Pitfalls

- Owning-function recovery is load-bearing here. On `hl-4554` the `"ScreenShake"` xref landed
  inside machine code that IDA had not assigned to the real entry; calling `add_func` at the xref
  instruction would have created a false function and poisoned signature generation. Recovery
  backtracks at most `0x200` bytes, requires exactly one raw instruction targeted by a direct near
  `call` from a defined caller, and fails closed on ambiguity. `hl-4554` emits the externally
  called entry `0x1D18260` (`func_size 0x123`); the former `xref_string_sources_as_function_starts`
  escape hatch was removed.
- The literal exists in more byte copies than the anchor needs (hl-8684 `hw.so` carries four
  `ScreenShake` matches, most of them `.symtab`/`.dynstr` entries such as `V_ScreenShake`). Only
  loaded, referenced string items contribute owners, and the exactly-one-survivor gate is what
  keeps this deterministic.
- `func_sig_allow_across_function_boundary` only *tags* the artifact unless signature generation
  is re-run with the flag; the flag lives in the finder's desired-fields list, never in the config
  symbol.
- Blob engines (`hl-3248`, `hl-3266`, `hl-3329`, `hl-3647`) are analyzed from the decrypted
  `hw.decrypt.dll` (the config still says `module_windows: hw.dll`). IDA may name the recovered
  entry `sub_XXXXXXXX`; match by artifact `func_va`, not the display name.
- Source/binary mismatch is expected and must not be "fixed": the public tree comments out the
  `FreeBlob` call and keeps a separate `ClientDLL_Shutdown`, while these binaries keep the
  secure-client path and inline Shutdown.
