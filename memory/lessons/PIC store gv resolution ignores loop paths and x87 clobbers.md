---
title: PIC store gv resolution ignores loop paths and x87 clobbers
type: note
permalink: goldsrc-vibesignatures/lessons/pic-store-gv-loop-and-x87-flow-model
tags:
- lesson
- preprocessor
- gv
- llm-decompile
---

# PIC store gv resolution ignores loop paths and x87 clobbers

## Trigger

`find-Mod_LoadModel-decompiles` failed on `svencoop-8948` Linux with `agent_failed` while
`loadname.linux.yaml` had already been written: the LLM-reported
`found_gv 'loadmodel' at 0x001785AE` was rejected by `_validate_llm_global_addresses` with
`unresolved_global_address: Cannot determine EBX base for [ebx+0x2747da0]`, the model then
dropped the entry on re-prompt, and `loadmodel.linux.yaml` was never emitted. The failure
aborted the rest of the `-allgamever` batch (`ida_analyze_bin.py` breaks on the first failing
tag unless `-skip_error`), so later gamevers silently lost coverage.

## Root cause

Two independent defects in the shared `_ADDRESS_FLOW_RESOLVER` model (both inside
`ida_analyze_util.py`) blocked `relative_store_address`; each one alone is enough to fail, so
fixing either in isolation does not help:

1. `resolve_address_flow` broke cycles by returning `None` for a revisited
   `(block, stop, register)` state and then required every predecessor value to agree, so a
   self-loop or a back edge that never writes the register poisoned the whole merge. The
   `Mod_LoadModel` body has both (`0x178680` self-loop, `0x1786B8 -> 0x1784BA` back edge).
2. The instruction walk treated every mnemonic outside its handled list as clobbering all
   eight general purpose registers, so the x87 `fld`/`fst`/`fld1`/`fxch`/`fucomip`/`fstp`
   sequence of the `developer_value > 1.0` comparison cleared EBX even though none of those
   instructions can write a GPR. The walk therefore returned a local `None` and never even
   reached the loop.

The first fix makes the second visible and vice versa: instrumenting `resolve_address_flow`
was necessary to stop guessing which one was live.

### Regression found in the first version of the cycle fix

Skipping every revisited-state predecessor was too weak a proof and turned an unknown into a
wrong answer: with the entry block setting `EBX = 0x8000` and a loop doing `add ebx, 4`, the
definition at the loop is `('offset', 4)`, so `resolve` recurses into the same block with a
smaller `stop`, merges the predecessor list, and the self-reference was skipped. Only the entry
constant survived, and the resolution returned `0x8004` where the baseline returned `None`. If
that value had landed in a mapped data segment the consumer would have accepted it and emitted
a wrong GV address instead of failing. The guard is therefore "the cycle never wrote the
register", which needs the ordered `path`, and both shapes are pinned by tests.

## Correct approach

- `resolve_address_flow`: skip a predecessor whose state is already on the current path **only
  when the cycle from that ancestor state back to the current state never wrote the register**.
  The value is then the one reaching the loop header. Any write on the cycle — `add reg, 4` per
  iteration, or a self-referential operand such as `('offset', 4)` whose base resolves to the
  same state — makes the value depend on the iteration count, so those cycles must keep failing
  closed. The path therefore has to be carried in order (`path`), not just as the `visiting`
  set: membership alone cannot tell a def-free cycle from an arithmetic one. If every
  predecessor is a skipped back edge, return `None`.
- Instruction walk: treat `wait`/`fnop` and `f*` as non-clobbering **only when no operand is
  an `o_reg` with `reg < 8`**. `fnstsw ax` / `fstsw ax` keep a GPR operand and must stay
  clobbers, otherwise the walk would silently keep a stale definition and could emit a wrong
  address instead of failing closed.

Both changes only convert previously-failed resolutions into resolved ones; they cannot change
an address that already resolved.

## Verification

- `uv run python -m unittest tests.test_ida_skill_preprocessor` — 109 tests OK.
  `test_address_flow_ignores_loop_paths_that_never_define_the_register` covers a self-loop plus
  a back edge and a loop that clobbers the register with `None`;
  `test_address_flow_rejects_cycles_that_write_the_register` pins the arithmetic counterexample
  above (both the cross-block and the same-block self-referential form, plus the def-free
  variant that must still resolve);
  `test_relative_store_ignores_x87_paths_that_cannot_define_the_base` drives the full
  inspector with synthetic IDA modules for `fld` (resolves) and `fnstsw ax` (stays `None`).
- Live: `-gamever svencoop-8948 ... -oldgamever none -debug` now succeeds and emits
  `loadmodel.linux.yaml` with `gv_sig_va 0x178480 + gv_inst_offset 0x12e = 0x1785AE`
  (`mov ds:(loadmodel - GOT)[ebx], esi`), `gv_inst_disp 0x2`, `gv_pic_addend 0x33a000`. That
  addend plus the embedded `0x2747da0` is exactly the `0x2a81da0` address IDA already reported
  in `data_refs`, i.e. the resolved value matches the independent xref.
- `-allgamever -modules engine -skill find-Mod_LoadModel-decompiles` finished with zero
  failures; all 11 engine configs emit `loadname`/`loadmodel` for every declared platform.

## Scope

Shared LLM-gv address resolution on x86-32 PE/ELF: any `found_gv` whose selected instruction
is a store or `lea` with a base register defined behind a loop or behind an FP-only
instruction. Not specific to `Mod_LoadModel`. The changes widen what resolves, and the first
version of the cycle rule showed the failure mode that makes that dangerous: an unsound skip
turns `None` into a plausible address rather than into a missing artifact, and the downstream
mapped-segment check cannot tell the difference. Keep both counter-example tests —
`fnstsw ax` and the arithmetic loop — whenever this rule is touched.
