---
title: Sys_InitMemory_HeapLimitPatches_1 locator
type: note
permalink: goldsrc-vibesignatures/locators/sys-initmemory-heaplimitpatches-1
tags:
  - locator
  - engine
  - patch
---

# Sys_InitMemory_HeapLimitPatches_1

## Symbol

- **Name**: `Sys_InitMemory_HeapLimitPatches_1`
- **Category**: `patch`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-Sys_InitMemory_HeapLimitPatches.py`

## Availability

- Declared in 10 engine configs: hl-3248, hl-3266, hl-3329, hl-3647, hl-4554, hl-6153, hl-8684, hl-10210, cof-5936, svencoop-10257.
- Platforms: Windows + Linux (finder is not platform-gated).
- Inlined / absent: present in every analyzed `Sys_InitMemory` body; index 1 exists because every inspected
  body contains at least two qualifying heap-limit immediates.

## Predecessors

- `Sys_InitMemory.{platform}.yaml`, consumed via `expected_input` (see the index-0 note for the full
  artifact-validation gate: `func_name` check, `func_va >= image_base`, `_inspect_function_via_mcp` re-check
  with the artifact's `func_sig_allow_across_function_boundary`).

## How it is located

Same enumeration as the rest of the series: the predecessor supplies the owner function, `py_eval` collects
every `mov`/`cmp` with a two-operand form whose second operand is an immediate in
`{0x2000000, 0x2800000, 0x8000000, 0x20000000}`, numbers them by instruction address order in the body
(starting at 0), and this artifact is the **second** site.

Per site the signature is forward-only from the instruction: the instruction's own bytes verbatim (immediate
included), then following instructions with branch/imm/mem/displ operands wildcarded. Expansion stops at the
first boundary of at least `max(6, instruction length)` bytes that matches the database exactly once at that
EA (caps 96 bytes / 64 instructions). `patch_va`/`patch_rva` are the instruction start, `patch_sig_disp` is
always `0`, and `patch_bytes` is deliberately omitted (the consumer re-decodes the instruction to locate the
immediate offset). Fail-closed gates: contiguous expected indices, site count equal to the declared count,
immediate still in the family, `patch_ea` inside the owner range, and `_find_unique_bytes(patch_sig) == patch_ea`.

Observed index-1 sites: hl-3248/3266/3329/3647/4554 `mov eax, 2800000h`; hl-6153/8684 (win)
`mov eax, 2800000h`; hl-8684 (lin) `cmp eax, 8000000h`; hl-10210 (win) `mov eax, 2800000h`;
hl-10210 (lin) `mov edx, 8000000h`; cof-5936 `cmp dword ptr [gv], 8000000h`;
svencoop-10257 (win) `cmp esi, 20000000h`; svencoop-10257 (lin) `cmp edi, 20000000h`.

## Pitfalls

- On hl-8684 the Linux body has only three qualifying sites while Windows has four, so index 1 exists on both
  platforms there but index 3 is Windows-only. Per-node index availability is not uniform across the family.
- Two svencoop-10257 Linux sites (indexes 0 and 6) share an identical 13-byte prefix
  (`81 FF 00 00 00 20 0F 9F C0 85 FF 0`); the forward-only expansion is what separates them. Shortening
  signatures or capping them more aggressively would break uniqueness for that node.
- The numbered identity is positional (address order in the body), so a rebuild that adds a qualifying
  immediate renumbers every later index.
- Patch artifacts never carry `patch_bytes`; the runtime consumer must decode the instruction itself.
