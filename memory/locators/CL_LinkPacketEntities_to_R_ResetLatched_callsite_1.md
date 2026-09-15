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

- Declared in 10 engine configs: cof-5936, hl-10210, hl-3248, hl-3266, hl-3329, hl-3647, hl-4554, hl-6153, hl-8684, svencoop-10257.
- Platforms: Windows + Linux where `hw.so` ships (hl-8684, hl-10210, svencoop-10257); the remaining seven configs are Windows binaries only.
- Inlined / absent: always present — this is the second of the two direct `R_ResetLatched` calls in `CL_LinkPacketEntities` (the `EF_NOINTERP` reset) and exists even on the configs where a third site is absent.

## Predecessors

- None declared. The finder resolves `CL_LinkPacketEntities` from its unique diagnostic literal and `R_ResetLatched` from the doubly-called-callee walk, then emits both endpoints and all call sites from one run.

## How it is located

1. `find-R_ResetLatched` recovers both endpoints first, writing the `R_ResetLatched` function artifact.
2. `locate_callsites(owner_ea, callee_ea)` walks `CL_LinkPacketEntities`'s instructions in address order and keeps every direct rel32 `CALL`/`JMP` (`E8`/`E9`, length `>= 5`) that references `R_ResetLatched`'s exact function start.
3. Sites are numbered from 0 in address order; this artifact is index **1**, the second call site.
4. The patch signature is generated from the branch instruction with its relative operand kept verbatim, then forward-expanded one instruction at a time (immediates/memory operands wildcarded) until the pattern is unique across all executable segments. `patch_sig_disp` is `0`; `patch_bytes` is omitted.
5. Uniqueness is re-verified (`_find_unique_bytes(patch_sig) == patch_ea`) before the YAML is written; the expected callsite count `0..N-1` must match the located count exactly.
6. Artifact fields: `patch_name`, `patch_va` (hex), `patch_rva` (`patch_va - image_base`), `patch_sig`, `patch_sig_disp`.

## Pitfalls

- Index `1` only exists because index `0` exists: the numbering is positional, so its identity depends on the address ordering of all direct branches from `CL_LinkPacketEntities` to `R_ResetLatched`.
- A change to the number of direct call sites (for example the extra hl-8684 Linux site) shifts which artifact index corresponds to which source-level call; the config's `expected_output` / `expected_output_linux` split is what keeps this deterministic per platform.
- Signature stability is bounded by the forward-expansion limit (`MAX_SIG_BYTES = 96`, `MAX_INSTRUCTIONS = 64`); if no unique pattern is found the site is rejected and the finder fails rather than emitting a weak signature.
