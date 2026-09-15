---
title: CL_LinkPacketEntities_to_R_ResetLatched_callsite_0 locator
type: note
permalink: goldsrc-vibesignatures/locators/cl-linkpacketentities-to-r-resetlatched-callsite-0
tags:
  - locator
  - engine
  - patch
---

# CL_LinkPacketEntities_to_R_ResetLatched_callsite_0

## Symbol

- **Name**: `CL_LinkPacketEntities_to_R_ResetLatched_callsite_0`
- **Category**: `patch`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-R_ResetLatched.py` (via `ida_preprocessor_scripts/_func_to_func_callsites_common.py`)

## Availability

- Declared in 10 engine configs: cof-5936, hl-10210, hl-3248, hl-3266, hl-3329, hl-3647, hl-4554, hl-6153, hl-8684, svencoop-10257.
- Platforms: Windows + Linux where `hw.so` ships (hl-8684, hl-10210, svencoop-10257); the remaining seven configs are Windows binaries only.
- Inlined / absent: always present — `CL_LinkPacketEntities` performs the full reset then the `EF_NOINTERP` reset, so at least two direct `R_ResetLatched` call sites exist in every build.

## Predecessors

- None declared. The finder resolves both endpoints itself: `CL_LinkPacketEntities` from its unique diagnostic literal and `R_ResetLatched` from the doubly-called-callee walk in the same script.

## How it is located

1. `find-R_ResetLatched` first recovers both endpoints (owner of `"Tried to link edict %i without model\n"`, and the doubly-called latched-reset candidate), writing the `R_ResetLatched` function artifact.
2. `locate_callsites(owner_ea, callee_ea)` then walks `idautils.FuncItems(CL_LinkPacketEntities)` in address order and keeps every instruction that is a **direct rel32 `CALL`/`JMP`** (`E8`/`E9` opcode, decoded length `>= 5`) whose xref set includes `R_ResetLatched`'s exact function start.
3. The surviving sites are numbered by address order starting at 0; this artifact is index **0**, the first (full-reset) call site.
4. For each site a unique patch signature is generated: the branch instruction's raw bytes are kept verbatim (relative operand included), then following instructions are appended with their immediate/memory operands wildcarded (`??`) until the byte pattern matches exactly once across all executable segments. `patch_sig_disp` is always `0` because the pattern starts at the branch itself; `patch_bytes` is omitted and the consumer computes the redirect at runtime.
5. The script re-verifies uniqueness (`_find_unique_bytes(patch_sig) == patch_ea`) and requires `patch_ea >= owner_ea`; any mismatch aborts the whole finder.
6. The expected number of callsite artifacts comes from the `expected_output` list and must be contiguous from 0; a mismatch between the located and expected counts fails closed.

## Pitfalls

- Index numbering is by **address order inside the owner body**, not by source order; adding or removing a call site renumbers the artifacts.
- Uniqueness is verified against current IDB bytes before writing; a non-unique signature is a hard failure, not a warning.
- The two calls in `CL_LinkPacketEntities` are semantically distinct (full reset then `EF_NOINTERP` reset), so both must stay address-ordered and separately signed.
- On hl-8684 Linux a third direct site exists (see `..._callsite_2`); the expected count for that platform is declared through `expected_output_linux`.
