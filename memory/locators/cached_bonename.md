---
title: cached_bonename locator
type: note
permalink: goldsrc-vibesignatures/locators/cached-bonename
tags:
  - locator
  - engine
  - gv
---

# cached_bonename

## Symbol

- **Name**: `cached_bonename`
- **Category**: `gv`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-R_StudioMergeBones-decompiles.py`
  (emits `cached_numbones` and `cached_bonename` from one run)

## Availability

- Declared in 10 configs: cof-5936, hl-10210, hl-3248, hl-3266, hl-3329, hl-3647,
  hl-4554, hl-6153, hl-8684, svencoop-10257.
- Platforms: Windows + Linux (no `platform:` gating).
- Inlined / absent: a static file-scope global array in `r_studio.c`, always present.

## Predecessors

- `R_StudioMergeBones.{platform}.yaml` (produced by
  `find-R_StudioDrawPlayerBody-decompiles`, consumed via `expected_input`; the LLM
  dependency policy marks it `"required"`).
- Reference disassembly: `references/{gamever}/engine/R_StudioMergeBones.{platform}.yaml`.

## How it is located

`-decompiles` (LLM) finder, run in the same batch as `cached_numbones`:

1. Load the required predecessor `R_StudioMergeBones.{platform}.yaml`.
2. Run the shared LLM-decompile contract (`prompt/call_llm_decompile.md`) with
   `expected_result_sections: ["found_gv"]`; the model selects the named-bone cache array
   that MergeBones reads, and the shared consumer resolves the operand to an address.
3. Emit the GV field set (`gv_name`, `gv_va`, `gv_rva`, `gv_sig`, `gv_sig_va`,
   `gv_inst_offset`, `gv_inst_length`, `gv_inst_disp`) plus
   `gv_sig_allow_across_function_boundary: true`.

## Pitfalls

- **Exact `cached_bonename` xrefs miss SaveBones.** The source declares 32-byte bone
  names, but the optimized `R_StudioSaveBones` starts its pointer at `name[0][31]` to read
  the trailing NUL and addresses the string as pointer-31. Any locator that only looks for
  the base label will find MergeBones and never the writer — which is exactly why the
  downstream `find-R_StudioSaveBones` intersects owners across `name+0..name+31`.
- The GV access anchor can differ between MergeBones and SaveBones (same target,
  different instruction). The selected anchor must agree with the emitted `gv_sig` owner.
- On SvEngine Linux the access may be register-relative with an embedded var-GOT dword;
  preserve `gv_pic_addend` (PR #105 address-recovery contract) or the runtime address will
  not resolve.
- Reference addresses are evidence only; never copy them across builds.

## Evidence

- The pair `cached_numbones` + `cached_bonename` is the DAG input for
  `find-R_StudioSaveBones`, where the 32-byte trailing-byte offset is handled explicitly.
