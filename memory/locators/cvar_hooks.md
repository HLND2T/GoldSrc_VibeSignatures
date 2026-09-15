---
title: cvar_hooks locator
type: note
permalink: goldsrc-vibesignatures/locators/cvar-hooks
tags:
  - locator
  - engine
  - gv
---

# cvar_hooks

## Symbol

- **Name**: `cvar_hooks`
- **Category**: `gv`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-cvar_hooks.py`

## Availability

- Declared in **2 configs only**: hl-10210 and hl-8684.
- Platforms: Windows + Linux (both declaring configs build both).
- Inlined / absent: **absent from every other engine build** — older `hl-*`, cof-5936 and
  svencoop-10257 are `native_unsupported`, not analysis gaps. The public engine leak has no hook
  list at all; HL25 added `cvarhook_t { hook, cvar, next }` plus `Cvar_HookVariable`. On Linux the
  DWARF/symtab name and the artifact name are both `cvar_hooks` (a 4-byte `.bss` pointer next to
  `cvar_vars`); the older artifact name was `cvar_callbacks`.

## Predecessors

- `Cvar_Set.{platform}.yaml` and `Cvar_DirectSet.{platform}.yaml` (both via `expected_input`).

## How it is located

1. Load both predecessor artifacts from the new binary dir, resolve their `func_va`, and confirm
   `Cvar_Set` still verifies in the live IDB via `_inspect_function_via_mcp` (its `func_sig` also
   becomes this artifact's `gv_sig`). Both must be function starts.
2. Inside the `Cvar_Set` body, collect the direct `call` instructions whose target resolves to the
   `Cvar_DirectSet` function start. **Exactly one** must exist.
3. Take the **immediate fall-through instruction** after that call (it must be the literal next
   instruction head, not merely the next reachable one) and decode it as a writable absolute
   32-bit load: mnemonic `mov`, destination a 32-bit GPR, source `o_mem`, with the encoded dword
   equal to the decoded address, 4-byte aligned, and inside a writable non-executable segment.
   On Windows this is `mov reg, [abs32]` (5 bytes, `disp 1`); on Linux the same shape is produced
   with the inlined `cvar_vars` load *before* the call so position matters.
4. Validate the reachable CFG from that instruction: the hook-node loop must compare `node+4`
   against the changed `cvar_t *` (`cmp` with a `[node_reg+4]` memory operand), advance through
   `node+8` (`mov node_reg, [node_reg+8]`), and invoke the callback either via
   `call [node_reg+0]` or via a register previously loaded from `[node_reg+0]`. All three
   predicates must hold.
5. Force-rename the resolved address to `cvar_hooks` in the IDB and require the rename to have
   taken effect.
6. Emit `gv_name`, `gv_va`, `gv_rva`, `gv_sig` (the `Cvar_Set` `func_sig`), `gv_sig_va`,
   `gv_inst_offset`, `gv_inst_length`, `gv_inst_disp`. Runtime resolution is
   `gv = *(uint32_t *)(match + gv_inst_offset + gv_inst_disp)`.

## Pitfalls

- The *immediate* fall-through is required. Linux `Cvar_Set` also loads the inlined `cvar_vars`
  **before** the `Cvar_DirectSet` call — never take the first absolute load in the function body.
- Never use an LLM `found_gv` here: the address is a global value (the list-head pointer) reached
  from a specific instruction, not a code-operand field, and the validating CFG shape is what
  separates the hook list from any other writable global loaded nearby.
- The reachable-set scan starts *at* the load instruction (heads below `load_ea` in the containing
  block are skipped), so the `cvar_vars` load earlier in the function cannot accidentally satisfy
  the `+4/+8/+0` predicates.
- Discovery must not use a byte signature or the old YAML; the artifact is re-derived from
  `Cvar_Set` + `Cvar_DirectSet` every run. If either predecessor is missing the finder returns
  False without scanning.
- Agent-produced YAML must normalize `gv_va`, `gv_rva`, `gv_sig_va`, `gv_inst_offset`,
  `gv_inst_length` and `gv_inst_disp` as quoted hex strings before runtime validation, or the
  runtime validator rejects the artifact.
- `gv_sig` is `Cvar_Set`'s signature, so re-running `find-Cvar_Set` (for example after a rename)
  changes this artifact too. The last such re-run produced byte-identical YAML, which is the
  expected regression signal.
- Consumers should prefer a successful `cvar_hooks` query over applying
  `Cvar_Set_to_Cvar_DirectSet_callsite_N` patches; on hl-8684/hl-10210 no callsite patch is
  emitted at all.
