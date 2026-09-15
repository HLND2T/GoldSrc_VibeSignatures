---
title: ClientDLL_Shutdown locator
type: note
permalink: goldsrc-vibesignatures/locators/clientdll-shutdown
tags:
  - locator
  - engine
  - func
---

# ClientDLL_Shutdown

## Symbol

- **Name**: `ClientDLL_Shutdown`
- **Category**: `func`
- **Module**: engine (`hw.dll`)
- **Producer**: `ida_preprocessor_scripts/find-ClientDLL_Shutdown.py`

## Availability

- Declared in 8 configs: cof-5936, hl-3248, hl-3266, hl-3329, hl-3647, hl-4554, hl-6153, hl-8684.
- Platforms: Windows-only (`platform: windows` on the finder registration; every declaring
  config is a Windows engine build anyway).
- Inlined / absent: **absent on hl-10210 and svencoop-10257**. HL25 inlines the Shutdown body
  into `ClientDLL_Init`; those two configs therefore register neither this finder nor a
  `ClientDLL_Shutdown` symbol, and `FreeBlob` is recovered from `ClientDLL_Init` instead. On
  hl-8684 Linux the body is likewise inlined into `ClientDLL_Init`, so the finder is gated to
  Windows there.

## Predecessors

- `ClientDLL_Init.{platform}.yaml` (produced by `find-ClientDLL_Init`, consumed via
  `expected_input`).

## How it is located

1. Load the `ClientDLL_Init.{platform}.yaml` artifact from the new binary dir and re-verify it in
   the live IDB with `_inspect_function_via_mcp` (function start plus `func_sig`, honouring the
   artifact's `func_sig_allow_across_function_boundary` flag). Any mismatch fails the finder.
2. Walk the direct `call` instructions inside the `ClientDLL_Init` body and collect every callee
   function start.
3. A callee survives only if it is a real function start, at least `0x40` bytes (`MIN_SHUTDOWN_SIZE`)
   in size, **and** `function_calls_unload_import` proves it calls `FreeLibrary` / `dlclose` —
   the check scans each `call`'s disassembled text, the callee name derived from its operand
   (`o_mem` / `o_displ` / `o_near` / `o_imm`) and every xref target name, looking for the
   case-insensitive substrings `freelibrary` or `dlclose`.
4. Exactly one callee must survive; the finder then force-renames it to `ClientDLL_Shutdown`.
5. Emits `func_name` / `func_va` / `func_rva` / `func_size` / `func_sig`, retrying the signature
   with `allow_across_function_boundary=True` (and recording the flag) when the in-function
   signature is not unique.

## Pitfalls

- The unload-import proof is the whole discrimination: the `FreeBlob` wrapper is itself a
  `ClientDLL_Init` callee, but it is both far smaller than `0x40` bytes and does not call
  `FreeLibrary`/`dlclose` (it calls a blob API function pointer). Size alone must not be used.
- `MIN_SHUTDOWN_SIZE = 0x40` is a hard floor; a build that stops inlining a trimmed Shutdown tail
  below that size would fail closed rather than emit a wrong function.
- The callee scan is restricted to the `ClientDLL_Init` body. When `ClientDLL_Init`'s artifact
  needs the across-boundary signature, that artifact's flag is propagated into the verification
  call so the re-check does not reject a legitimately long signature.
- Blob engines (`hl-3248`, `hl-3266`, `hl-3329`, `hl-3647`) are analyzed from the decrypted
  `hw.decrypt.dll`; IDA may keep the callee named `sub_XXXXXXXX`. The finder renames it on
  success — match by artifact `func_va`, not the display name.
