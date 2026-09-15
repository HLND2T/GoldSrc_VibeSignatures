---
title: R_StudioChangePlayerModel locator
type: note
permalink: goldsrc-vibesignatures/locators/r-studiochangeplayermodel
tags:
  - locator
  - engine
  - func
---

# R_StudioChangePlayerModel

## Symbol

- **Name**: `R_StudioChangePlayerModel`
- **Category**: `func`
- **Module**: engine (`hw.dll` / `hw.so`) — Windows builds only
- **Producer**: `ida_preprocessor_scripts/find-R_StudioChangePlayerModel.py`

## Availability

- Declared in 10 engine configs, but gated `platform: windows`: hl-3248, hl-3266, hl-3329,
  hl-3647, hl-4554, hl-6153, hl-8684, hl-10210, cof-5936, svencoop-10257.
- Platforms: **Windows-only**. The config declares `platform: windows`; the finder also
  returns `False` outright when `platform != "windows"`.
- Inlined / absent: on Linux builds (hl-8684/10210 hw.so and svencoop hw.so) the routine is
  inlined into `studioapi_SetupPlayerModel` — zero direct calls survive, so the symbol does
  not exist as a standalone entry there even though a copy may survive for external linkage.
  On hl-6153/hl-8684/hl-10210 Windows MSVC merges the two source call sites into one, but the
  function itself is still a standalone entry.

## Predecessors

- `studioapi_SetupPlayerModel` (produced by `find-studioapi_SetupPlayerModel{,-svencoop}`,
  consumed via `expected_input`).

## How it is located

1. Load the verified `studioapi_SetupPlayerModel` artifact; require its `func_va` to be a
   function start in the current IDB.
2. Identify `currententity`: collect the base registers of `[reg+0x0B94]` accesses
   (`CURRENTENTITY_MODEL_OFFSET`, `currententity->model`), then keep the plain absolute
   `mov reg, [abs]` loads (`o_mem`, no index) whose destination register is one of those
   bases. Exactly one such global must remain — composed array reads reuse the same register
   and must not contribute.
3. Enumerate the owner's direct `E8` call sites. Keep those whose next instruction is not
   `add esp, N` with `N > 0` (that is cdecl argument cleanup; the callee is
   `void (void)`, zero arguments).
4. Deduplicate by target while counting call sites.
5. Accept the unique callee that (a) references the `currententity` global, (b) contains the
   `0Bh` immediate (`MAX_SKINS == 11`) and (c) contains `0FFFFFFFFh` (topcolor/bottomcolor
   reset) in its disassembly.
6. Emit the `func` artifact; the returned `call_sites` count feeds the callsite finder's
   expectation.

## Pitfalls

- `Host_IsSinglePlayerGame` is also a zero-argument callee of the owner but references none
  of `currententity` / `0Bh` / `0FFFFFFFFh`; `Q_strncpy` carries three arguments and is
  filtered by the `add esp, N` test.
- Structured operand extraction only for `currententity`: a raw byte-window scan decodes
  opcode bytes into mapped `.data` addresses.
- Call-site count differs by build and must be verified empirically — do not assume "newer
  build merges". Known counts: WON-era hl-3248/3266/3329/3647, hl-4554, svencoop and cof keep
  two; hl-6153/8684/10210 merge to one.
- Discovery never uses a byte signature or a prior artifact signature.
