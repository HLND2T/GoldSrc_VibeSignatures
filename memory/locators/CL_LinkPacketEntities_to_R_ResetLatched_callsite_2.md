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

- **Name**: `CL_LinkPacketEntities_to_R_ResetLatched_callsite_2`
- **Category**: `patch`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-R_ResetLatched.py` (via `ida_preprocessor_scripts/_func_to_func_callsites_common.py`)

## Availability

- Declared in exactly **1** engine config: hl-8684.
- Platforms: **Linux-only** — the artifact is `CL_LinkPacketEntities_to_R_ResetLatched_callsite_2.linux.yaml`; hl-8684 declares it through `expected_output_linux`.
- Inlined / absent: this third direct `R_ResetLatched` call site exists only in the hl-8684 Linux build. Every other registered config (and the hl-8684 Windows build) has exactly two sites, so index 2 must not be expected there.

## Predecessors

- None declared. Both endpoints are recovered inside `find-R_ResetLatched`: `CL_LinkPacketEntities` from the unique `"Tried to link edict %i without model\n"` owner, `R_ResetLatched` from the doubly-called-callee walk.

## How it is located

1. The same walk as the other call sites: `locate_callsites(owner_ea, callee_ea)` enumerates `CL_LinkPacketEntities`'s instructions in address order and keeps direct rel32 `CALL`/`JMP` instructions (`E8`/`E9`, length `>= 5`) that reference `R_ResetLatched`'s exact function start.
2. The hl-8684 Linux build issues three such branches; this artifact is index **2**, the last one in address order.
3. The patch signature starts at the branch instruction with its relative operand preserved and is forward-expanded with wildcarded immediates/memory operands until unique across all executable segments. `patch_sig_disp = 0`; `patch_bytes` is omitted.
4. The finder requires the located count to equal the expected count extracted from `expected_output` + `expected_output_linux` (here 2 base + 1 Linux = 3 for hl-8684 Linux, 2 for hl-8684 Windows). Any mismatch aborts the whole finder.
5. Uniqueness of the signature is re-verified before writing.

## Pitfalls

- This artifact's very existence is the platform-gating contract: if it were declared for all configs, every other target would fail on a count mismatch.
- Index numbering is positional (address order), so the third site's identity is only stable as long as the other two remain address-ordered ahead of it.
- The extra site is a real codegen difference on hl-8684 Linux, not a locator artifact — do not try to reproduce it on Windows.
