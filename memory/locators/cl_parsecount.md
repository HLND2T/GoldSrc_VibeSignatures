---
title: cl_parsecount locator
type: note
permalink: goldsrc-vibesignatures/locators/cl-parsecount
tags:
  - locator
  - engine
  - gv
---

# cl_parsecount

## Symbol

- **Name**: `cl_parsecount`
- **Category**: `gv`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-R_DrawTEntitiesOnList-decompiles.py`

## Availability

- Declared in 10 engine configs: cof-5936, hl-10210, hl-3248, hl-3266, hl-3329, hl-3647, hl-4554, hl-6153, hl-8684, svencoop-10257.
- Platforms: Windows + Linux.
- Inlined / absent: none observed; it is the mutable frame parser counter, always addressable.

## Predecessors

- `R_DrawTEntitiesOnList` (produced by `find-R_DrawTEntitiesOnList`, consumed via `expected_input` and `dependency_policy: required`). The finder returns `False` when the predecessor, the exported function, or the stack-displacement probe is unavailable.

## How it is located

1. Load `R_DrawTEntitiesOnList.{platform}.yaml`, read `func_va`, and export the function via `_export_llm_function` (disassembly + pseudocode).
2. Probe actual encoded `ESP` displacements with `build_stack_operand_export_py_eval` — only `o_displ`/`o_phrase` operands whose register set is exactly `['esp']` with 4-byte dtype contribute. This deliberately ignores IDA's *named* stack variables.
3. `ida_scalar.recover_masked_index_stride(disasm_code, stack_displacements=...)` independently recovers the frame stride on the target: it finds the `and reg, <mask-or-counter>` seed, then walks up to 96 instructions forward, breaking at joins/jumps/rets/loops/unknown mnemonics, tracking coefficients through `mov`/`lea`/`add`/`sub`/`inc`/`dec`/`imul`/`shl`/`sal`/`xor`, and requires the value to reach a `StudioDrawPlayer` call (`call ... [reg+8]`, i.e. the studio interface's `+8` slot, directly or via a register forwarded from such a call).
4. The frame argument is taken as the second pushed call argument (`[esp+4]`; stored values at displacement 4 are accepted when flags were spilled) or `stores[4]`. `INC`/`DEC` of the independent entity index preserves its zero coefficient. Constants and independent globals are coefficient 0; unknown arithmetic, partial-register writes, conflicting paths and `[esp+d]` overwrites fail closed.
5. Require a single unique stride in `(0x4000, 0xFFFFFFFF]` (`MIN_FRAME_STRIDE`): the 0x154 entity-state multiplier must never be selected.
6. `cl_parsecount` itself is then an LLM `found_gv` spec (prompt `prompt/call_llm_decompile.md`, reference `references/{gamever}/engine/R_DrawTEntitiesOnList.{platform}.yaml`). Comment in the finder: *"cl.parsecount may be a register-relative member, including Sven Linux. Reference semantics distinguish it from CL_UPDATE_MASK; the shared CFG address resolver proves the register base. Operand spelling alone cannot identify it."*
7. Emitted fields: `gv_name`, `gv_va`, `gv_rva`, `gv_sig`, `gv_sig_va`, `gv_inst_offset`, `gv_inst_length`, `gv_inst_disp`, plus `gv_sig_allow_across_function_boundary:true`.

Concrete anchor shapes from current artifacts (evidence only): hl-10210 Windows `gv_va 0x11282a84`, offset `0x32d`, length 6, disp 2 (`mov eax, ds:...`); hl-8684 Linux offset `0x2c3`, length 6, disp 2. In the CoF reference the counter load is `mov eax, cl_parsecount` immediately followed by `and eax, CL_UPDATE_MASK` and `imul eax, 42C0h`.

## Pitfalls

- **Counter vs mask (CoF caveat).** On CoF both sides of the `AND` are memory-backed: the counter at `0x2e115a4` has independently verified parser writes, while the mask at `0x1eae664` starts at `0x3f` and only supplies `AND` operands. A canonical HL reference alone let an LLM choose the *mask*. Always use the officially generated cof-5936 `R_DrawTEntitiesOnList` reference, which distinguishes the mutable counter load from `CL_UPDATE_MASK`. This is a real body difference — never fix it by copying fixed addresses into discovery.
- **Sven Linux register-relative member.** A Linux operand-shape rule once declared every register-relative member load a decoy, which rejected the real Sven counter and accepted a PIC `const LEA naming the mask`. Correct approach: drop spelling-based restrictions and let the shared CFG address resolver prove the base. On the analyzed Sven binary `CL_UPDATE_MASK` is at `0x2F1654` (initialized to 63) and `cl.parsecount` is at client base `0x15D7D60 + 0x242324 = 0x181A084`. Those addresses are evidence for that binary only.
- The mask is *immutable* (a constant bit mask); the counter is *mutable* and has parser stores. Only the counter satisfies the anchor contract.
- The stride value recovered in step 3-5 is supplied to `size_of_frame` as `expected_value`; it is never hardcoded from a reference build.
