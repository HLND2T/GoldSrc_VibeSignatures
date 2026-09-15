---
title: g_phClientModule locator
type: note
permalink: goldsrc-vibesignatures/locators/g-phclientmodule
tags:
  - locator
  - engine
  - gv
---

# g_phClientModule

## Symbol

- **Name**: `g_phClientModule`
- **Category**: `gv`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-ClientDLL_HudInit-decompiles.py` (the
  `LLM_DECOMPILE` half of the same finder that deterministically emits `cl_enginefuncs` / `cl_funcs`)

## Availability

- Declared in 10 configs: cof-5936, hl-10210, hl-3248, hl-3266, hl-3329, hl-3647, hl-4554,
  hl-6153, hl-8684, svencoop-10257.
- Platforms: Windows + Linux, but `svencoop-10257` declares `g_phClientModule` as
  `platform: windows` (and registers the finder Windows-only), so Linux artifacts exist only for
  hl-10210 and hl-8684.
- Inlined / absent: the global always exists; what varies is where the engine copies it out of.
  On HL25 Windows the reference instruction is `mov esi, hClientDLL` inside `ClientDLL_HudInit`
  (`ClientDLL_HudInit + 0x23`, a 6-byte `mov reg, [abs32]`).

## Predecessors

- `ClientDLL_HudInit.{platform}.yaml` (`dependency_policy: required`) and
  `ClientDLL_Init.{platform}.yaml` (both in `expected_input`).

## How it is located

1. This symbol is the `LLM_DECOMPILE` half of `find-ClientDLL_HudInit-decompiles`; it runs only
   after the deterministic `_write_direct_globals` phase has successfully emitted
   `cl_enginefuncs` and `cl_funcs` (that phase is a hard gate).
2. `LLM_DECOMPILE` spec: `symbol_name = g_phClientModule`, reference
   `references/{gamever}/engine/ClientDLL_HudInit.{platform}.yaml`, `expected_result_sections:
   ["found_gv"]`. The predecessor reference is required to be present; the access is already
   annotated there (`mov esi, hClientDLL ; target: g_phClientModule`).
3. `preprocess_common_skill` feeds the annotated reference to the LLM, which returns a `found_gv`
   entry naming the instruction that reaches the global. The entry is re-validated:
   `_inspect_llm_instruction` on the reported `insn_va`, and on Linux the displacement-based
   global address must resolve (`_validate_llm_global_addresses` rejects an
   `unresolved_global_address` — the LLM must pick another instruction referencing the same global
   rather than substitute a computed address).
4. The owning function of that instruction is inspected as an `__llm_anchor` to produce
   `gv_sig` / `gv_sig_va`; when the plain signature is not unique and
   `gv_sig_allow_across_function_boundary` is in the desired fields, the across-boundary variant is
   used.
5. Emits `gv_name`, `gv_va`, `gv_rva`, `gv_sig`, `gv_sig_va`, `gv_inst_offset`, `gv_inst_length`,
   `gv_inst_disp` (and `gv_sig_allow_across_function_boundary: true` when applicable).

## Pitfalls

- This is the only symbol in the family that still depends on the LLM transport. Everything the
  reference annotates must be preserved verbatim (`insn_disasm` keeps the real operand text); the
  LLM is told to report the canonical identity and never an anonymous `sub_XXXXXXXX` /
   `dword_XXXXXXXX` name.
- On Linux the loader-displacement global may not resolve from an arbitrary instruction; the
  validator deliberately fails such entries instead of accepting a calculated address. Do not
  "help" it by rewriting the displacement.
- The predecessor is `ClientDLL_HudInit`, not `ClientDLL_Init`. Although `ClientDLL_Init` is also
  declared as an input, `g_phClientModule` is read out of the HudInit body; a reference taken from
  the wrong owner yields a valid-looking instruction and a wrong signature.
- Sven Linux has no `ClientDLL_HudInit` artifact at all (the finder and its `-decompiles`
  consumer are Windows-gated in svencoop-10257), so this symbol is Windows-only there — the
  capability matrix marks the combination unsupported rather than missing.
- Blob engines (`hl-3248`, `hl-3266`, `hl-3329`, `hl-3647`) are analyzed from the decrypted
  `hw.decrypt.dll`; IDA may display the global as `dword_XXXXXXXX`. Match by artifact `gv_va`, not
  the display name.
