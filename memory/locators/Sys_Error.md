---
title: Sys_Error locator
type: note
permalink: goldsrc-vibesignatures/locators/sys-error
tags:
  - locator
  - engine
  - func
---

# Sys_Error

## Symbol

- **Name**: `Sys_Error`
- **Category**: `func`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-Sys_Error.py`

## Availability

- Declared in 10 engine configs: hl-3248, hl-3266, hl-3329, hl-3647, hl-4554, hl-6153, hl-8684, hl-10210, cof-5936, svencoop-10257.
- Platforms: Windows + Linux. Producer is not platform-gated; Linux artifacts exist for hl-8684, hl-10210,
  svencoop-10257.
- Inlined / absent: none observed. `Sys_Error` is a real standalone entry in every analyzed build; its
  prologue is *shared* with the `Con_Printf`-family wrappers, which is a signature problem, not an
  existence problem.

## Predecessors

- None. `find-Sys_Error` has no `expected_input`.

## How it is located

1. `xref_strings = ["FATAL ERROR (shutting down): %s"]` — substring match (the note records the anchor with a
   trailing `\n`, the script does not require it). `XrefsTo` on the literal maps to the owning function(s)
   through `_ensure_function_owner`; exactly one candidate must survive.
2. Signature generation runs with the `func_sig_allow_across_function_boundary` option, declared in the
   finder as `"func_sig_allow_across_function_boundary:true"` inside `GENERATE_YAML_DESIRED_FIELDS`. The
   option is threaded into the spec (`spec["allow_across_function_boundary"] = True`) and into
   `_inspect_function_via_mcp`, raising the signature caps from `max_fixed 24 / max_tokens 64` to
   `256 / 256`. Without it the prologue-capped signature matched 5 addresses and `_find_unique_bytes`
   returned `None`, failing the preprocessor.
3. Once the signature is unique it is verified again by `_find_unique_bytes` against the function start; the
   emitted YAML also carries `func_sig_allow_across_function_boundary: true` so later runs (`preprocess_func_sig_via_mcp`
   honors `old_data`) keep the extended budget.
4. Emitted fields: `func_name`, `func_sig`, `func_va`, `func_rva`, `func_size`,
   `func_sig_allow_across_function_boundary`.

## Pitfalls

- **Shared prologue.** `Sys_Error` is variadic and formats through a 1024-byte stack buffer, so its entry
  bytes are byte-identical to the `Con_Printf`-family wrappers (on hl-3248 four lookalikes; on cof-5936 two
  share a 42-byte prologue and diverge ~110 tokens in). The extended across-boundary window is mandatory —
  do not remove `func_sig_allow_across_function_boundary:true` from the finder.
- The flag can only lift the caps at *generation* time: a pre-seeded old YAML with a long signature does not
  help on its own, because `_inspect_function_via_mcp` regenerates and re-validates the signature internally.
- The string anchor still uniquely identifies the function (1 candidate); the cap problem is purely in
  signature uniqueness, so never fall back to LLM/byte-sig discovery for this symbol.
- Regression RVAs: hl-10210 hw.dll `0x21fc20`, hw.so `0xd4770`, svencoop-10257 hw.dll `0xabb050`,
  hw.so `0xaf0a0`. hl-10210 hw.dll artifact size `0x12c`.
