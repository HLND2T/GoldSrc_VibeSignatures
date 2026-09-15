---
title: studioapi_SetupPlayerModel_to_R_StudioChangePlayerModel_callsite_0 locator
type: note
permalink: goldsrc-vibesignatures/locators/studioapi-setupplayermodel-to-r-studiochangeplayermodel-callsite-0
tags:
  - locator
  - engine
  - patch
---

# studioapi_SetupPlayerModel_to_R_StudioChangePlayerModel_callsite_0

## Symbol

- **Name**: `studioapi_SetupPlayerModel_to_R_StudioChangePlayerModel_callsite_0`
- **Category**: `patch`
- **Module**: engine (`hw.dll` only)
- **Producer**: `ida_preprocessor_scripts/find-studioapi_SetupPlayerModel_to_R_StudioChangePlayerModel_CallSites.py`
  (logic in `ida_preprocessor_scripts/_func_to_func_callsites_common.py`)

## Availability

- Declared in 10 engine configs: hl-3248, hl-3266, hl-3329, hl-3647, hl-4554, hl-6153,
  hl-8684, hl-10210, cof-5936, svencoop-10257. Every one of them declares it (the first
  call site always exists).
- Platforms: **Windows-only** (`platform: windows`; the shared helper accepts
  `windows`/`linux` but the config only schedules Windows).
- Inlined / absent: on Linux the callee is inlined into the owner, so no direct branch
  survives and this artifact is not produced.

## Predecessors

- `studioapi_SetupPlayerModel` (owner) and `R_StudioChangePlayerModel` (callee), both consumed
  via `expected_input`. The owner artifact is additionally re-verified through MCP before any
  patch is written.

## How it is located

1. Parse `expected_outputs` into a contiguous, zero-based index list
   (`expected_callsite_outputs`); a gap or a duplicate name fails the finder.
2. Load the owner and callee artifacts; re-inspect the owner function via MCP (honouring the
   owner's `func_sig_allow_across_function_boundary`) and require the inspected `func_va` to
   equal the artifact's.
3. Enumerate the owner's `FuncItems` and keep every direct rel32 `call`/`jmp` (`E8`/`E9`) whose
   `XrefsFrom` resolves to the callee's function start.
4. For each surviving branch, generate a forward-only patch signature starting at the branch:
   the branch's own bytes are kept verbatim, subsequent instructions are wildcarded at their
   operand displacement bytes (imm/near/far/mem/displ `offb..offb+dtype_size`, plus the rel32
   tail of `E8/E9/EB` and the `0F 8x` tail), then the signature is extended instruction by
   instruction (max 96 bytes / 64 instructions) until `count_matches` over the executable
   segments returns exactly 1.
5. Require `len(sites) == len(expected)`; sites are numbered by owner-body instruction address
   order starting at 0, so this file is always the lowest-address branch.
6. Re-verify uniqueness with `_find_unique_bytes` for each `patch_sig` before writing.

## Pitfalls

- `patch_va`/`patch_rva` are the **signature match start**, which here is the branch
  instruction itself; `patch_sig_disp` is always `0`. `patch_bytes` is omitted — the consumer
  computes the redirect at runtime.
- The finder is used by SCModelDownloader to redirect these branches to its own wrapper
  instead of hooking `R_StudioChangePlayerModel` globally.
- Call-site count is build-dependent: HL25-era hl-6153/8684/10210 keep only call site 0, while
  WON-era hl builds, hl-4554, cof and svencoop keep both. This is why
  `callsite_1` is declared in only 7 configs while `callsite_0` is declared in all 10.
- A single non-unique signature anywhere in the list aborts the whole finder (it emits no
  partial result).
