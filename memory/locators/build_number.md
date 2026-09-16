---
title: build_number locator
type: note
permalink: goldsrc-vibesignatures/locators/build-number
tags:
  - locator
  - engine
  - func
---

# build_number

## Symbol

- **Name**: `build_number`
- **Category**: `func`
- **Module**: engine (`hw.dll` / `hw.so`)
- **Producer**: `ida_preprocessor_scripts/find-build_number.py`

## Availability

- Declared in 10 engine configs: hl-3248, hl-3266, hl-3329, hl-3647, hl-4554, hl-6153, hl-8684, hl-10210, cof-5936, svencoop-10257.
- Platforms: Windows + Linux (producer is not platform-gated).
- Inlined / absent: `build_number` has **no string anchor of its own** — it is the small accessor that
  `SV_SendServerinfo` calls to format the build number. It is recovered as a call target, not by scanning
  for a literal, so it must be resolved separately on every platform node.

## Predecessors

- `SV_SendServerinfo.{platform}.yaml` (produced by `find-SV_SendServerinfo` / `find-SV_SendServerinfo-svencoop`),
  declared `required` in the LLM spec's `dependency_policy` and consumed via `expected_input`. The live
  artifact supplies the target `func_va` used as the comparison target.

## How it is located

This is a Pattern E (`-decompiles`) finder: a symbolic `LLM_DECOMPILE` spec instead of a string anchor.

1. `TARGET_FUNCTION_NAMES = ["build_number"]`, no `FUNC_XREFS`. The fast path
   (`preprocess_func_sig_via_mcp(..., old_yaml_map=old_yaml_map)`) may carry the symbol forward when a usable
   previous artifact exists.
2. The `LLM_DECOMPILE` spec names `prompt/call_llm_decompile.md`, the annotated reference
   `references/{gamever}/engine/SV_SendServerinfo.{platform}.yaml`, `expected_result_sections = ["found_call"]`
   and `dependency_policy = {"SV_SendServerinfo.{platform}.yaml": "required"}`.
3. The contract loader requires the reference to be a `{func_name, func_va, disasm_code, procedure}` mapping
   and requires the *live* `SV_SendServerinfo` artifact (from the current `new_binary_dir`) to exist with a
   `func_va`; the annotated reference and the live predecessor are then compared side by side by the model.
4. The model returns `found_call` entries. Each entry's instruction is re-inspected
   (`_inspect_llm_instruction`) and must resolve to exactly one unique code target; that target is passed to
   `_inspect_function_via_mcp`, which generates the artifact.
5. Emitted fields: `func_name`, `func_sig`, `func_va`, `func_rva`, `func_size`.

## Pitfalls

- `build_number` is not a literal-anchored symbol. Any attempt to give it its own string/signature anchor
  would be guessing; the only evidence chain is "the call `SV_SendServerinfo` makes to format its build
  number".
- Reference resolution: `references/{gamever}/engine/SV_SendServerinfo.{platform}.yaml` only exists for
  **hl-10210** and **svencoop-10257**; every other gamever falls back to `GSVIBE_REFERENCE_GAMEVER`
  (default `hl-10210`) through `_resolve_reference_resource`. That fallback is intentional, so a
  cross-binary/cross-platform reference comparison is expected — addresses must never be assumed to align.
- The dependency contract is strict: if the platform's `SV_SendServerinfo` artifact is missing or has no
  `func_va`, `_prepare_llm_context` returns `None` and the symbol fails closed rather than falling back to an
  unconstrained search.
- The recovered call target must be a real function entry resolvable by IDA; a tail-call/thunk target that
  `_inspect_function_via_mcp` cannot turn into a unique function (with signature validation) does not emit.
  `find-build_number` does **not** enable `func_sig_allow_across_function_boundary` or
  `func_sig_resolve_jmp_thunk`, so tiny wrappers/thunks are handled only through the normal entry path.
- The `SV_SendServerinfo` reference body differs between the hl family and SvEngine, which is why the
  predecessor itself has two producers (`find-SV_SendServerinfo-svencoop` on svencoop-10257).

## Platform caveats

`build_number` is not a stored constant — it is derived from the compile-time `__DATE__`, so
the Windows and Linux engines of one release report different values, and the repository's
`svencoop-<N>` tag tracks the **Windows** value. Concretely: `svencoop-8948` is 8948 on
`hw.dll` but 8997 on `hw.so`; `svencoop-10257` is 10257 on `hw.dll` but 10269 on `hw.so`.
See [[Sven Co-op engine build_number differs between Windows and Linux]] for the derivation
formula and verification evidence before trusting any build number read from a Linux binary.
