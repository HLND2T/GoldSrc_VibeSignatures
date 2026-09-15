---
title: Sys_InitMemory_HeapLimitPatches_2 locator
type: note
permalink: goldsrc-vibesignatures/locators/sys-initmemory-heaplimitpatches-2
tags:
  - locator
  - engine
  - patch
---

# Sys_InitMemory_HeapLimitPatches_2

## Symbol

- **Name**: `Sys_InitMemory_HeapLimitPatches_2`
- **Category**: `patch`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-Sys_InitMemory_HeapLimitPatches.py`

## Availability

- Declared in 10 engine configs: hl-3248, hl-3266, hl-3329, hl-3647, hl-4554, hl-6153, hl-8684, hl-10210, cof-5936, svencoop-10257.
- Platforms: Windows + Linux (finder is not platform-gated).
- Inlined / absent: present on every analyzed node; the smallest inspected body (hl-8684 Linux) still has
  three qualifying sites, so index 2 exists everywhere.

## Predecessors

- `Sys_InitMemory.{platform}.yaml`, consumed via `expected_input`. The finder requires the artifact's
  `func_name`, re-inspects the function through `_inspect_function_via_mcp` (honoring the artifact's
  `func_sig_allow_across_function_boundary`), and aborts if the re-inspected `func_va` differs.

## How it is located

The series is enumerated, not anchored: the predecessor fixes the owner, and `py_eval` walks the owner's
instruction list keeping `mov`/`cmp` with exactly two operands whose second is an immediate in
`{0x2000000, 0x2800000, 0x8000000, 0x20000000}`. Sites are numbered by instruction address order in the body
from 0; this artifact is the **third** site.

Signature construction is forward-only from the instruction: verbatim bytes for the instruction itself
(immediate included), wildcarded branch/imm/mem/displ operands for the instructions that follow. Expansion
stops at the first boundary of at least `max(6, instruction length)` bytes that matches exactly once in the
database at that EA (caps 96 bytes / 64 instructions). `patch_va`/`patch_rva` are the instruction start;
`patch_sig_disp` is always `0`; `patch_bytes` is omitted by design (the consumer re-decodes the instruction
to find the immediate offset). Fail-closed gates: contiguous expected index list, located count equal to the
declared count, immediate still in the family, `patch_ea` inside the owner range,
`_find_unique_bytes(patch_sig) == patch_ea`.

Observed index-2 sites: hl-3248/3266/3329/3647/4554 `cmp eax, 2000000h`; hl-6153/8684 (win)
`cmp eax, 8000000h`; hl-8684 (lin) `mov eax, 8000000h`; hl-10210 (win) `cmp esi, 8000000h`;
hl-10210 (lin) `mov esi, 8000000h`; cof-5936 `mov dword ptr [gv], 8000000h`;
svencoop-10257 (win) `cmp esi, 20000000h`; svencoop-10257 (lin) `mov dword ptr [esi+10h], 20000000h`.

## Pitfalls

- The immediate family is validated per site, but the *union* is what the script checks; the family
  separation (32/40/128MB vs 512MB) is an observed property of the bodies, not something the finder enforces.
  A future body mixing families would silently renumber indexes.
- cof-5936 reuses a single global for indexes 0, 1, 2, 3, 4 and 5 — signatures there differ only in the
  extension bytes after the `C7 05 <gv> <imm>` prefix. Do not shorten them.
- svencoop-10257 Linux index 2 writes through a struct displacement (`C7 46 10 ...`), so the addressing form
  differs from the Windows binaries; nothing may assume a global-operand shape.
- Positional numbering means an added/removed qualifying immediate in a future build shifts every later
  index — treat the index as build-specific metadata, and re-derive from the emitted artifact rather than
  hard-coding a site.
