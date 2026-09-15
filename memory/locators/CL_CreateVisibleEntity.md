---
title: CL_CreateVisibleEntity locator
type: note
permalink: goldsrc-vibesignatures/locators/cl-createvisibleentity
tags:
  - locator
  - engine
  - func
---

# CL_CreateVisibleEntity

## Symbol

- **Name**: `CL_CreateVisibleEntity`
- **Category**: `func`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-CL_CreateVisibleEntity.py` (thin wrapper over `ida_preprocessor_scripts/_engine_public_callback_common.py`)

## Availability

- Declared in 10 engine configs: cof-5936, hl-10210, hl-3248, hl-3266, hl-3329, hl-3647, hl-4554, hl-6153, hl-8684, svencoop-10257.
- Platforms: Windows + Linux.
- Inlined / absent: none observed. It is a `cl_enginefunc_t` table entry, so the table slot always exists; only the number of forwarding hops to the real body varies. hl-10210 Windows body is 0x67 bytes.

## Predecessors

- `cl_enginefuncs` (consumed via `expected_input`). That artifact is produced by `find-ClientDLL_HudInit-decompiles` on HL/CoF and by `find-ClientDLL_Init-pic-enginefuncs` on SvEngine Linux.

## How it is located

1. Load `cl_enginefuncs.{platform}.yaml`, read `gv_va`, and compute `entry = gv_va + 61 * 4` — SDK `cl_enginefunc_t` slot 61 is `CL_CreateVisibleEntity`.
2. `target = ida_bytes.get_dword(entry)`.
3. `unwrap(target)` follows forwarding shims, iteratively:
   - a single-instruction `jmp rel32` → its destination;
   - a straight-line wrapper of ≤16 instructions whose only non-PC-thunk callee is exactly one `call rel32` → that callee. A callee is rejected as a PC thunk when it is a 2-instruction `mov reg,[esp]; retn` body.
   - Any other mnemonic, a non-near call operand, or a `mov` whose destination is not a register / whose operand is outside `[esp`/`[ebp` aborts the walk and returns the current target.
   - The loop tracks `seen` and fails closed on a cycle.
4. Validate: not 64-bit, target is in an executable segment, and `ida_funcs.get_func(target).start_ea == target`.
5. `_inspect_function_via_mcp` emits `func_name`, `func_va`, `func_rva`, `func_size`, `func_sig`; if strict entry inspection fails, the payload is re-inspected with `func_sig_allow_across_function_boundary: true` (the emitted YAML then carries that flag).

## Pitfalls

- SvEngine inserts a forwarding API shim, so the raw slot value is usually a wrapper rather than the body — following it is mandatory, but it must be a *proven* tail `jmp` or a single-callee straight-line shim. Address adjacency is never used.
- The unwrap must reject cycles even when every node is a valid executable function entry (covered by a synthetic two-node jump-cycle regression).
- Windows `func_sig` is emitted without `allow_across_function_boundary` for hl-10210, i.e. the 0x67-byte body is unique on its own; only the fallback path adds the flag.
- The downstream `-decompiles` finder has the riskiest trap in this family: `CL_CreateVisibleEntity` inserts either into the *visible* set or into the *beam* set, and only the non-beam branch is the `cl_numvisedicts`/`cl_visedicts` anchor. See `cl_numvisedicts` / `cl_visedicts`.
