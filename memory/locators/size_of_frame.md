---
title: size_of_frame locator
type: note
permalink: goldsrc-vibesignatures/locators/size-of-frame
tags:
  - locator
  - engine
  - scalar
---

# size_of_frame

## Symbol

- **Name**: `size_of_frame`
- **Category**: `scalar`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-R_DrawTEntitiesOnList-decompiles.py`

## Availability

- Declared in 10 engine configs: cof-5936, hl-10210, hl-3248, hl-3266, hl-3329, hl-3647, hl-4554, hl-6153, hl-8684, svencoop-10257.
- Platforms: Windows + Linux.
- Inlined / absent: not applicable — the symbol is a *numeric scalar*, not an address. There is no instruction, function or VA for it; consumers use the value directly, bound to the binary identity.

## Predecessors

- `R_DrawTEntitiesOnList` (produced by `find-R_DrawTEntitiesOnList`, consumed via `expected_input` and `dependency_policy: required`). The finder returns `False` if the predecessor is missing, the export fails, or the affine trace raises.

## How it is located

1. Same predecessor export and ESP-displacement probe as `cl_parsecount` (see that file, steps 1-2).
2. `recover_masked_index_stride` traces the masked-index coefficient through register copies, `IMUL`, `LEA`, shifts and constant additions/subtractions until it reaches the `StudioDrawPlayer` argument, yielding the frame byte stride for the *current* binary. The minimum-size filter `MIN_FRAME_STRIDE = 0x4000` is only a coarse exclusion of entity-state indexing (the `0x154` multiplier) — it is never the semantic locator.
3. The recovered value becomes the spec's `expected_value` and is passed to the LLM `found_scalar` spec (prompt `prompt/call_llm_decompile.md`, reference `references/{gamever}/engine/R_DrawTEntitiesOnList.{platform}.yaml`).
4. Shared validation requires the LLM's `scalar_value` to equal the independently recovered `expected_value`; mismatches retry, and missing/conflicting values are rejected.
5. Artifact contract (`scalar_artifact.SCALAR_FIELDS`): **exactly** `scalar_name` and `scalar_value`. `scalar_name` must be a nonempty string; `scalar_value` must be a plain `int` (not `bool`) in `[0, 0xFFFFFFFF]`. There are **no** signature, instruction-address, or `gv_inst_*` fields — this was the user-approved numeric scalar contract (Issue #106 comment 5636344998), replacing an earlier imm32-only proposal.

Current values (evidence for those binaries only, never cross-build fallbacks): hl-3248..hl-8684 `17080` (0x42B8); hl-10210 `17176` (0x4318); cof-5936 `17088` (0x42C0); svencoop-10257 `34072` (0x8518).

## Pitfalls

- **No single machine-code immediate.** hl-3248's pseudocode shows `17080`, but the machine code computes it through a strength-reduced chain (9 → 72 → 71 → 213 → 427 → 2135 → 17080). Compiler strength reduction changes the *encoding*, not the `frame_t` byte size — do not look for an `imm32`.
- Never hardcode a reference build's value; it is recovered per binary and validated against the current target.
- Pseudocode "typed-element" coefficients need byte-unit validation against the actual arithmetic — Hex-Rays may scale an index by an element size while the real operand is already a byte count.
- `SCALAR_FIELDS` is a strict two-field set: adding any extra key (e.g. a signature) fails `validate_scalar_artifact`, and legacy snapshots cannot contain scalar fields (they must be rebuilt through the current pipeline; index stays 4).
- The same trace also feeds `cl_parsecount`; a `ValueError("no unique masked frame-ring stride reaches StudioDrawPlayer")` aborts both outputs, so the two symbols always appear together.

## Evidence

- Raw per-binary evidence (SHA-256 hashes, instruction traces, snapshot/Pages quality checks, existing-output comparison): [[issue-106 size_of_frame engine evidence]].
