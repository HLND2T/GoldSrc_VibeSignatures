---
title: Sys_InitMemory_HeapLimitPatches_0 locator
type: note
permalink: goldsrc-vibesignatures/locators/sys-initmemory-heaplimitpatches-0
tags:
  - locator
  - engine
  - patch
---

# Sys_InitMemory_HeapLimitPatches_0

## Symbol

- **Name**: `Sys_InitMemory_HeapLimitPatches_0`
- **Category**: `patch`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-Sys_InitMemory_HeapLimitPatches.py`

## Availability

- Declared in 10 engine configs: hl-3248, hl-3266, hl-3329, hl-3647, hl-4554, hl-6153, hl-8684, hl-10210, cof-5936, svencoop-10257.
- Platforms: Windows + Linux (the finder is not platform-gated; Linux nodes exist for hl-8684, hl-10210,
  svencoop-10257).
- Inlined / absent: present wherever `Sys_InitMemory` is; index 0 always exists because every inspected body
  contains at least one immediate from the heap-limit family.

## Predecessors

- `Sys_InitMemory.{platform}.yaml` (produced by `find-Sys_InitMemory` / `find-Sys_InitMemory-svencoop`),
  consumed via `expected_input`. The finder reads the artifact, requires `func_name == "Sys_InitMemory"` and
  `func_va >= image_base`, then re-verifies the function through `_inspect_function_via_mcp`
  (`allow_across_function_boundary` taken from the artifact's own
  `func_sig_allow_across_function_boundary` field).

## How it is located

The patch series is enumerated per body, not anchored per site: the predecessor gives the owner, and every
qualifying instruction inside its `[start, end)` range becomes one artifact.

1. `py_eval` walks `FuncItems(owner.start_ea)`, clamped to the owner range, and keeps instructions whose
   mnemonic is `mov` or `cmp`, that have exactly two non-void operands, whose second operand is an immediate,
   and whose immediate (masked to 32 bits) is in the union heap-limit family
   `{0x2000000, 0x2800000, 0x8000000, 0x20000000}` (32MB / 40MB / 128MB / 512MB). The union is used uniformly
   because the two engine families never mix there.
2. Surviving sites are numbered by **instruction address order in the body, starting at 0**; index 0 is the
   first qualifying instruction.
3. For each site a forward-only signature is built starting *at* the instruction: the target instruction's
   bytes are emitted verbatim (its immediate included), and each following instruction is appended with its
   branch/imm/mem/displ operand bytes wildcarded (`E8/E9/EB` → wildcard from byte 1, `0F 8x` → from byte 2,
   `70..7F` → from byte 1). Expansion stops at the first boundary that is `>= max(6, instruction length)`
   and matches exactly one address in the whole database, equal to the instruction EA (caps: 96 bytes /
   64 instructions).
4. `patch_va` / `patch_rva` are the **instruction start**, never the immediate's own four bytes;
   `patch_sig_disp` is always `0` because the signature begins at the instruction; `patch_bytes` is not
   emitted — the consumer re-decodes the instruction to find its immediate offset before writing.
5. Fail-closed gates: the expected output set must be a contiguous `0..N-1` index list derived from the
   artifact filenames, the located site count must equal `N`, every immediate must still be in the family,
   every `patch_ea` must lie inside the owner range, and `_find_unique_bytes(patch_sig)` must return exactly
   `patch_ea`.
6. Emitted fields: `patch_name`, `patch_va`, `patch_rva`, `patch_sig`, `patch_sig_disp`.

Observed index-0 sites: hl-3248/3266/3329/3647/4554 `cmp eax, 2800000h`; hl-6153/8684 (win)
`mov eax, 8000000h`; hl-8684 (lin) `mov eax, 2800000h`; hl-10210 (win) `mov esi, 8000000h`;
hl-10210 (lin) `cmp edx, 8000000h`; cof-5936 `mov dword ptr [gv], 8000000h`;
svencoop-10257 (win) `mov dword ptr [gv], 20000000h`; svencoop-10257 (lin) `cmp edi, 20000000h`.

## Pitfalls

- The target instruction's own immediate is part of `patch_sig`. The signature is therefore valid only
  against the original (unpatched) bytes — that is intended, since HeapPatch writes the new immediate after
  the match.
- The same global is hit repeatedly (cof-5936 uses one `gv` for indexes 0, 1, 2, 3, 4 and 5). Do not assume
  one patch per address or per global; identity comes solely from the numbered artifact.
- Index ↔ site mapping is positional, so it is only stable while the body's qualifying set is unchanged.
  Adding or removing a qualifying immediate in a future build would renumber every later patch.
- `patch_sig_disp` is always `0`; a non-zero value is rejected, so a consumer must not expect a
  signature-to-target offset.
- If the located count differs from the declared expected-output count the whole run fails closed rather
  than emitting a partial series.
