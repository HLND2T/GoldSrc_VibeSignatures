---
title: Sys_InitMemory_HeapLimitPatches_5 locator
type: note
permalink: goldsrc-vibesignatures/locators/sys-initmemory-heaplimitpatches-5
tags:
  - locator
  - engine
  - patch
---

# Sys_InitMemory_HeapLimitPatches_5

## Symbol

- **Name**: `Sys_InitMemory_HeapLimitPatches_5`
- **Category**: `patch`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-Sys_InitMemory_HeapLimitPatches.py`

## Availability

- Declared in 2 of the 10 engine configs: **cof-5936** (platform-agnostic `expected_output`, so all of that
  config's platforms) and **svencoop-10257** (`expected_output_linux` only, i.e. **Linux-only** there).
- Its svencoop-10257 Windows counterpart does not exist: the Windows body has only five qualifying
  immediates (`_0.._4`), while the Linux body has seven (`_0.._6`).
- Platforms: cof-5936 Windows; svencoop-10257 Linux.

## Predecessors

- `Sys_InitMemory.{platform}.yaml`, consumed via `expected_input`. svencoop-10257's Linux node is produced by
  `find-Sys_InitMemory-svencoop` from the `FULLMATCH:/proc/meminfo` anchor; cof-5936's from
  `find-Sys_InitMemory`. The finder validates `func_name` / `func_va`, re-inspects the function through
  `_inspect_function_via_mcp` with the artifact's `func_sig_allow_across_function_boundary`, and requires the
  re-inspected VA to match.

## How it is located

Sites are not anchored individually: the predecessor fixes the owner, and `py_eval` enumerates the owner's
instructions keeping `mov`/`cmp` with exactly two operands whose second is an immediate in
`{0x2000000, 0x2800000, 0x8000000, 0x20000000}`. They are numbered by instruction address order in the body
from 0; this artifact is the **sixth** site of that enumeration.

Each site's signature is forward-only starting at the instruction: the instruction's bytes verbatim (its
immediate included), followed by the subsequent instructions with branch/imm/mem/displ operands wildcarded
(`E8/E9/EB` from byte 1, `0F 8x` from byte 2, `70..7F` from byte 1). Expansion stops at the first boundary of
at least `max(6, instruction length)` bytes that matches exactly once in the database at that EA (caps 96
bytes / 64 instructions). `patch_va`/`patch_rva` are the instruction start, `patch_sig_disp` is always `0`,
`patch_bytes` is omitted (the consumer re-decodes the instruction to locate the immediate offset). Fail-closed
gates: contiguous expected index list, located count equal to the declared count, immediate still in the
family, `patch_ea` inside the owner range, `_find_unique_bytes(patch_sig) == patch_ea`.

Observed index-5 sites: cof-5936 `mov dword ptr [gv], 8000000h`; svencoop-10257 (lin)
`cmp edi, 20000000h`.

## Pitfalls

- **Linux-only on svencoop-10257.** The config declares `_5` (and `_6`) under `expected_output_linux`; the
  Windows node stops at `_4`. Adding the index to the platform-agnostic `expected_output` would break the
  Windows count gate.
- The Linux sites here are PIC and reach the global/GOT through `cmp edi, imm`-style forms; the instruction
  start is still the patch VA even when the displacement lives elsewhere.
- The two svencoop-10257 Linux sites with identical prefixes (`81 FF 00 00 00 20 0F 9F C0 85 FF 0` at this
  index and index 6) require the forward-only expansion to grow past the shared prefix; do not shorten the
  signature.
- Positional numbering: a change in the qualifying set renumbers all later indexes.
