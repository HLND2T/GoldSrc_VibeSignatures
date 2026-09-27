---
title: CL_LinkPacketEntities_to_R_ResetLatched_callsite_1 locator
type: note
permalink: goldsrc-vibesignatures/locators/cl-linkpacketentities-to-r-resetlatched-callsite-1
tags:
  - locator
  - engine
  - patch
---

# CL_LinkPacketEntities_to_R_ResetLatched_callsite_1

## Symbol

- **Name**: `CL_LinkPacketEntities_to_R_ResetLatched_callsite_1`
- **Category**: `patch`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-R_ResetLatched.py` (via `ida_preprocessor_scripts/_func_to_func_callsites_common.py`)

## Availability
- Declared in 11 engine configs (hl-3248/3266/3329/3647/4554/6153/8684/10210, svencoop-8948/10257, cof-5936).
- Present on all 15 configured engine/platform targets: 11 Windows and four Linux.
- Exactly two direct `R_ResetLatched` call sites exist in the verified `CL_LinkPacketEntities` body on every target.
## Predecessors
- `find-CL_LinkPacketEntities` supplies the independently verified owner artifact. `find-R_ResetLatched` consumes it and identifies the unique reset callee before emitting both numbered call sites.
## How it is located
1. Revalidate the current-binary `CL_LinkPacketEntities` artifact, then identify `R_ResetLatched` from exactly two direct calls plus its other entity-linking callers.
2. `locate_callsites(owner_ea, callee_ea)` keeps exact direct rel32 `CALL`/`JMP` sites to the verified reset function. Require exactly two sites; this artifact is index **1** in address order.
3. Generate a unique patch signature from the branch and following instructions, wildcarding non-stable operand bytes as the shared helper requires. Reverify uniqueness before writing. `patch_sig_disp = 0`; runtime redirect bytes are not stored.
## Pitfalls
- The old hl-8684 Linux artifact at index 1 pointed to `CL_InterpolateModel.part.1`, because the old reset locator accepted a three-call interpolation core. The corrected target is `R_ResetLatched` at `0x1367b0`; callsite 1 is now `0x17e187` for that exact binary.
- Callsite numbering is by instruction address. The two calls have different source roles (full reset, then `EF_NOINTERP` reset); never use index alone to infer an unverified target.
- The former Linux-only `callsite_2` is retired; it was an interpolation call, not a reset. See [[Engine entity interpolation locators (issue 266)]].