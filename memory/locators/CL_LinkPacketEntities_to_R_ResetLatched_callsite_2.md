---
title: CL_LinkPacketEntities_to_R_ResetLatched_callsite_2 locator
type: note
permalink: goldsrc-vibesignatures/locators/cl-linkpacketentities-to-r-resetlatched-callsite-2
tags:
  - locator
  - engine
  - patch
---

# CL_LinkPacketEntities_to_R_ResetLatched_callsite_2

## Symbol
- **Name**: `CL_LinkPacketEntities_to_R_ResetLatched_callsite_2` (retired)
- **Category**: historical `patch` artifact
- **Module**: engine (`hw.so`, `hl-8684`)
- **Former producer**: `ida_preprocessor_scripts/find-R_ResetLatched.py`
## Availability
- Retired after issue #266 validation. This symbol is no longer declared by any engine config, and its Linux YAML artifact was removed.
- The former `hl-8684/hw.so` address was a call to `CL_InterpolateModel.part.1`, not a third `R_ResetLatched` call.
## Predecessors
- This historical entry has no active finder output. The surviving reset callsites consume the verified `CL_LinkPacketEntities` predecessor artifact.
## How it is located
- Historical record only. The former `hl-8684/hw.so` candidate at `0x17e09a` belongs to the interpolation path. The actual `R_ResetLatched` at `0x1367b0` has exactly two direct callsites in `CL_LinkPacketEntities`, at `0x17deb9` and `0x17e187`.
- The corrected finder enforces a count of two and writes only `callsite_0` and `callsite_1`.
## Pitfalls
- The former `R_ResetLatched` candidate at `0x17b4a0` is `CL_InterpolateModel.part.1`. The old three-callsite result arose from selecting that callee by caller count.
- Do not restore the third artifact without rechecking the destination of each direct branch against the actual reset function in IDA.