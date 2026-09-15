---
title: R_StudioDrawModel locator
type: note
permalink: goldsrc-vibesignatures/locators/r-studiodrawmodel
tags:
  - locator
  - engine
  - func
---

# R_StudioDrawModel

## Symbol

- **Name**: `R_StudioDrawModel`
- **Category**: `func`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-R_StudioDrawModel.py`,
  `ida_preprocessor_scripts/find-R_StudioDrawModel-svencoop.py`
  (both delegate to `_studio_player_model_common.preprocess_studio_draw_model`)

## Availability

- Declared in 10 configs: cof-5936, hl-10210, hl-3248, hl-3266, hl-3329, hl-3647,
  hl-4554, hl-6153, hl-8684, svencoop-10257.
- Platforms: Windows + Linux (no `platform:` gating).
- Inlined / absent: always present as a standalone function start (stored at
  `studio+4`). The dead-player branch that calls `R_StudioDrawPlayer` is folded into a
  GCC `.part.N` cold clone on Linux, so the call edge is corroboration only.

## Predecessors

- `R_StudioDrawPlayer.{platform}.yaml` (produced by `find-R_StudioDrawPlayer` /
  `-svencoop`, consumed via `expected_input`).

## How it is located

1. Re-run the same `&pStudioAPI` locator as `R_StudioDrawPlayer`: unique
   ClientDLL_CheckStudioInterface diagnostic (HL wording for the generic finder, SvEngine
   wording for `-svencoop`), candidate must be writable data whose static dword points at
   the writable `studio` object `{1, +4, +8}`, `dword0 == 1`, `+4`/`+8` executable exact
   function starts, exactly one surviving candidate. Absolute operands on Windows/non-PIC
   Linux, GOT-anchored `lea reg,[ebx+disp32]` on SvEngine Linux (the locator collapses on
   the candidate VA, not the string owner — Linux can have two owners).
2. Hard gate: the located `studio+8` dword must **equal** the verified
   `R_StudioDrawPlayer` artifact `func_va` from the DAG. That equality fixes the interface
   identity, so by elimination the `+4` slot is `R_StudioDrawModel`. A mismatch aborts.
3. The source's dead-player branch calls `R_StudioDrawPlayer` directly from
   `R_StudioDrawModel`; the direct call/jmp family of the `+4` entry is recorded as
   corroboration (the `direct_transfer_targets` of the entry). On Linux GCC keeps this edge
   inside a `.part.N` clone, so it is never required.
4. Materialize through `_inspect_function_via_mcp` at `studio+4`, requiring
   `func_va == draw_ea`; fall back to `allow_across_function_boundary=True` (emitting
   `func_sig_allow_across_function_boundary: true`) when the strict window is ambiguous.

## Pitfalls

- The `+8 == R_StudioDrawPlayer artifact` equality is the whole identity proof — never
  accept a `studio` object candidate on layout alone, and never copy addresses across
  builds.
- SvEngine's Linux image is PIC; the raw embedded dword is not the address.
- The GCC `.part.N` clone means the "R_StudioDrawModel calls R_StudioDrawPlayer" edge is
  missing on Linux; do not use its absence to reject a candidate.
- Discovery never uses a byte signature or an old artifact signature.

## Evidence

- Validated 2026-09-10 (`studio+4` / `studio+8`): hl-10210 `hw.dll`
  `0x101F35E0` / `0x101F0580`, hl-10210 `hw.so` `0xD28E0` / `0xD28B0`, hl-8684
  `0x1D84AF0` / `0x1D853B0`, hl-3248 `0x1D8E5C0` / `0x1D8EED0`, svencoop-10257 `hw.dll`
  `0x1D90580` / `0x1D8A390`, svencoop-10257 `hw.so` `0xAD840` / `0xAD7F0`, cof-5936
  `0x1DBE9EF` / `0x1DBF4F1`.
