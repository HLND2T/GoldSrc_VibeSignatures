---
title: Sys_InitMemory_HeapLimitPatches_6 locator
type: note
permalink: goldsrc-vibesignatures/locators/sys-initmemory-heaplimitpatches-6
tags:
  - locator
  - engine
  - patch
---

# Sys_InitMemory_HeapLimitPatches_6

## Symbol

- **Name**: `Sys_InitMemory_HeapLimitPatches_6`
- **Category**: `patch`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-Sys_InitMemory_HeapLimitPatches.py`

## Availability

- Declared in **one** config only: **svencoop-10257**, and there **Linux-only**
  (`expected_output_linux`, no Windows counterpart).
- The SvEngine Windows body stops at five qualifying immediates (`_0.._4`); only the Linux body has seven.
  This is the highest index in any config and the last artifact of the series.
- Platforms: Linux-only (`hw.so`).

## Predecessors

- `Sys_InitMemory.linux.yaml`, produced by `find-Sys_InitMemory-svencoop` from the `FULLMATCH:/proc/meminfo`
  anchor, consumed via `expected_input`. The finder validates `func_name` and `func_va >= image_base`,
  re-inspects the function through `_inspect_function_via_mcp` (honoring the artifact's
  `func_sig_allow_across_function_boundary`) and requires the re-inspected VA to be unchanged.

## How it is located

The predecessor fixes the owner function; `py_eval` walks the owner's instructions and keeps every `mov`/`cmp`
with exactly two operands whose second is an immediate, masked to 32 bits and checked against
`{0x2000000, 0x2800000, 0x8000000, 0x20000000}`. Qualifying sites are numbered by instruction address order
in the body starting at 0; this artifact is the **seventh and last** site.

Its signature is forward-only from the instruction: the instruction's own bytes verbatim (immediate included),
then the following instructions with branch/imm/mem/displ operand bytes wildcarded, expanding until a boundary
of at least `max(6, instruction length)` bytes matches the database exactly once at that EA (caps 96 bytes /
64 instructions). `patch_va`/`patch_rva` are the instruction start, `patch_sig_disp` is always `0`, and
`patch_bytes` is omitted on purpose — the consumer re-decodes the instruction to find the immediate offset
before writing. Fail-closed gates: contiguous expected index list, located count equal to the declared count,
immediate still in the family, `patch_ea` inside the owner range,
`_find_unique_bytes(patch_sig) == patch_ea`.

Observed index-6 site: svencoop-10257 (lin) `cmp edi, 20000000h`, whose signature shares its first 13 bytes
(`81 FF 00 00 00 20 0F 9F C0 85 FF 0`) with index 0 of the same body.

## Pitfalls

- It is the only Linux-only, single-config index of the series: adding it to any other gamever's expected
  outputs (or to the shared `expected_output` of svencoop-10257) fails the count gate for those nodes.
- The first 13 signature bytes are identical to index 0's; uniqueness is achieved only by the forward
  expansion. Any change that truncates or re-wildcards the trailing instructions breaks this artifact.
- Because it is the last index, it is the first to disappear if a future SvEngine Linux body loses a
  qualifying immediate — and the entire series then fails closed rather than emitting a partial set.
- Positional numbering: the index is build-specific, so re-derive the VA from the emitted artifact instead of
  hard-coding `0x…`.
