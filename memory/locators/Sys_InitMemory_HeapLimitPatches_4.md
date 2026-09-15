---
title: Sys_InitMemory_HeapLimitPatches_4 locator
type: note
permalink: goldsrc-vibesignatures/locators/sys-initmemory-heaplimitpatches-4
tags:
  - locator
  - engine
  - patch
---

# Sys_InitMemory_HeapLimitPatches_4

## Symbol

- **Name**: `Sys_InitMemory_HeapLimitPatches_4`
- **Category**: `patch`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-Sys_InitMemory_HeapLimitPatches.py`

## Availability

- Declared in only 2 of the 10 engine configs: **cof-5936** and **svencoop-10257**. Both declare it under the
  platform-agnostic `expected_output`, so it is produced for every analyzed platform of those two configs
  (cof-5936 Windows; svencoop-10257 Windows and Linux).
- The index exists because those two bodies are the largest: cof-5936 has six qualifying immediates and
  svencoop-10257 has five (Windows) / seven (Linux).
- Platforms: Windows + Linux where declared.

## Predecessors

- `Sys_InitMemory.{platform}.yaml`, consumed via `expected_input`. For the svencoop-10257 node the artifact
  comes from `find-Sys_InitMemory-svencoop`; for cof-5936 from `find-Sys_InitMemory`. The finder validates
  `func_name` and `func_va >= image_base`, re-inspects the function with `_inspect_function_via_mcp` (honoring
  the artifact's `func_sig_allow_across_function_boundary`) and requires an unchanged VA.

## How it is located

The predecessor fixes the owner function; `py_eval` walks the owner's instruction list and keeps `mov`/`cmp`
instructions with exactly two operands whose second is an immediate in
`{0x2000000, 0x2800000, 0x8000000, 0x20000000}` (lifted to 32 bits before comparison). Qualifying sites are
numbered by instruction address order in the body starting at 0, and this artifact is the **fifth** site.

Signature generation is forward-only from the instruction: the instruction's own bytes verbatim (immediate
included) plus wildcarded branch/imm/mem/displ operand bytes for the following instructions, expanding to the
first boundary of at least `max(6, instruction length)` bytes that matches exactly once in the database at
that EA (caps 96 bytes / 64 instructions). `patch_va`/`patch_rva` are the instruction start, `patch_sig_disp`
is always `0`, `patch_bytes` is omitted (the consumer re-decodes the instruction to find the immediate
offset). Fail-closed gates: contiguous expected index list, located count equal to the declared count,
immediate still in the family, `patch_ea` inside the owner range, `_find_unique_bytes(patch_sig) == patch_ea`.

Observed index-4 sites: cof-5936 `cmp dword ptr [gv], 8000000h`; svencoop-10257 (win)
`mov esi, 20000000h; mov dword ptr [gv], esi`; svencoop-10257 (lin) `mov dword ptr [esi+10h], 20000000h`.

## Pitfalls

- Declared in only two configs — never infer this index from another gamever's artifact set, and do not add
  it to a config whose body has fewer qualifying immediates: the count gate rejects the whole run.
- cof-5936 reaches this index over a single reused global (`[gv]` appears at indexes 0/1/2/3/4/5 with
  128MB/40MB values); the signatures only stay unique because of the bytes that follow the `C7 05 <gv> <imm>`
  prefix.
- svencoop-10257 Windows index 4 is a two-instruction site (`BE 00 00 00 20` then `89 35 ...`); the
  instruction-start rule means `patch_va` points at the `mov esi, 20000000h`, not at the store.
- Positional numbering: shifts if a future build changes the qualifying set.
