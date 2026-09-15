---
title: Sys_InitMemory_HeapLimitPatches_3 locator
type: note
permalink: goldsrc-vibesignatures/locators/sys-initmemory-heaplimitpatches-3
tags:
  - locator
  - engine
  - patch
---

# Sys_InitMemory_HeapLimitPatches_3

## Symbol

- **Name**: `Sys_InitMemory_HeapLimitPatches_3`
- **Category**: `patch`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-Sys_InitMemory_HeapLimitPatches.py`

## Availability

- Declared in 10 engine configs: hl-3248, hl-3266, hl-3329, hl-3647, hl-4554, hl-6153, hl-8684, hl-10210,
  cof-5936, svencoop-10257.
- Platforms: Windows + Linux, **except hl-8684**, where `_3` is declared under `expected_output_windows`
  only. The hl-8684 Linux body has just three qualifying immediates, so the index does not exist there.
- Inlined / absent: this is the first index in the series that is not universally present; it is absent on
  hl-8684 Linux by construction (declared count 3 for that node).

## Predecessors

- `Sys_InitMemory.{platform}.yaml`, consumed via `expected_input`. The finder validates `func_name` and
  `func_va >= image_base`, re-inspects the function with `_inspect_function_via_mcp` (honoring the artifact's
  `func_sig_allow_across_function_boundary`), and requires the re-inspected VA to be unchanged.

## How it is located

The predecessor fixes the owner; `py_eval` then walks the owner's instructions and keeps `mov`/`cmp` with
exactly two operands whose second is an immediate in `{0x2000000, 0x2800000, 0x8000000, 0x20000000}`. Sites
are numbered by instruction address order in the body from 0; this artifact is the **fourth** site. The
per-platform expected-output count is what makes the "Windows has four sites, Linux has three" split work:
the finder requires the located site count to equal the declared count exactly and fails closed otherwise.

Each site gets a forward-only signature starting at the instruction: verbatim bytes for the instruction
(immediate included), wildcarded branch/imm/mem/displ operands for the following instructions, expanding to
the first boundary of at least `max(6, instruction length)` bytes that matches the database exactly once at
that EA (caps 96 bytes / 64 instructions). `patch_va`/`patch_rva` are the instruction start, `patch_sig_disp`
is always `0`, and `patch_bytes` is omitted so the consumer re-decodes the instruction to locate the
immediate offset.

Observed index-3 sites: hl-3248/3266/3329/3647/4554 and hl-10210/6153/8684 (win) `mov dword ptr [gv], imm`
with the build's 128MB/32MB value; cof-5936 `mov dword ptr [gv], 2800000h` (its one 40MB site);
svencoop-10257 (win) `cmp esi, 20000000h`.

## Pitfalls

- **Platform split.** hl-8684 is Windows-only for this index (`expected_output_windows`), while
  hl-3248/3266/3329/3647/4554/6153/10210/cof-5936/svencoop-10257 declare it under the platform-agnostic
  `expected_output`. Do not "fix" a hl-8684 Linux run by adding the index — that node genuinely has three
  sites and would fail the count gate.
- cof-5936's index 3 is the only 40MB site in that body (indexes 0/1/2/4/5 are 128MB), which is exactly the
  "cof-5936 shows both 0x2800000 and 0x8000000 despite buildnum < 6153" case: never gate 0x8000000 on
  `buildnum >= 6153`.
- Windows artifacts for this index are frequently `mov dword ptr [gv], imm` — the global address sits inside
  the signature prefix, so the signature is build-specific by design.
- Positional numbering: a future body gaining or losing a qualifying immediate renumbers every later index.
