---
title: cached_numbones locator
type: note
permalink: goldsrc-vibesignatures/locators/cached-numbones
tags:
  - locator
  - engine
  - gv
---

# cached_numbones

## Symbol

- **Name**: `cached_numbones`
- **Category**: `gv`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-R_StudioMergeBones-decompiles.py`
  (emits `cached_numbones` and `cached_bonename` from one run)

## Availability

- Declared in 10 configs: cof-5936, hl-10210, hl-3248, hl-3266, hl-3329, hl-3647,
  hl-4554, hl-6153, hl-8684, svencoop-10257.
- Platforms: Windows + Linux (no `platform:` gating).
- Inlined / absent: it is a static file-scope global in `r_studio.c`; always present. The
  *access form* differs (absolute operand on Windows, PIC/GOTOFF on SvEngine Linux).

## Predecessors

- `R_StudioMergeBones.{platform}.yaml` (produced by
  `find-R_StudioDrawPlayerBody-decompiles`, consumed via `expected_input`; the LLM
  dependency policy marks it `"required"`).
- Reference disassembly: `references/{gamever}/engine/R_StudioMergeBones.{platform}.yaml`.

## How it is located

`-decompiles` (LLM) finder — no deterministic anchor of its own:

1. Load the required predecessor `R_StudioMergeBones.{platform}.yaml`.
2. Run the shared LLM-decompile contract (`prompt/call_llm_decompile.md`) over that
   function's annotated reference with `expected_result_sections: ["found_gv"]`. The model
   picks the global access that is `cached_numbones` (the bone-count cache that
   MergeBones reads), and the shared consumer resolves the operand to an address.
3. Emit the GV field set: `gv_name`, `gv_va`, `gv_rva`, `gv_sig`, `gv_sig_va`,
   `gv_inst_offset`, `gv_inst_length`, `gv_inst_disp`, plus
   `gv_sig_allow_across_function_boundary: true`.

## Pitfalls

- `cached_numbones` has **multiple legitimate accesses** in the binary (MergeBones, and the
  SaveBones writer). The same-target/different-anchor risk is real: a pure in-memory probe
  of the shared consumer showed that list reversal changes the chosen GV anchor and can
  change its target. The finder therefore pins selection to the verified MergeBones
  reference rather than to a bare xref scan.
- The emitted `gv_sig` is the owner function's signature; `gv_inst_offset`/`gv_inst_disp`
  locate the operand inside it. Resolve the disp against the owner's PIC addend on SvEngine
  Linux, where an embedded dword can be var-GOT rather than an address (the
  `cl_parsefuncs`-linux / PR #105 contract: `gv_pic_addend` is preserved when present).
- Reference addresses are evidence only — never copy them across builds.
- Do not use the exact `cached_bonename` xref set to find `cached_numbones` (or vice
  versa); see `cached_bonename` for the trailing-NUL offset trap.

## Evidence

- Emitted together with `cached_bonename` by the same finder run; the pair is the DAG input
  for `find-R_StudioSaveBones`.
