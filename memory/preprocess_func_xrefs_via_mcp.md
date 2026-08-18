---
title: preprocess_func_xrefs_via_mcp
type: note
permalink: goldsrc-vibesignatures/preprocess-func-xrefs-via-mcp
---

# preprocess_func_xrefs_via_mcp + func_sig_allow_across_function_boundary

## What it is

Deterministic function-locator path used by Pattern A finders (`find-<func>.py`) inside `preprocess_common_skill`. It builds a JSON spec, runs it through `_FUNC_XREF_PY_EVAL_TEMPLATE` against the bound IDA DB, and requires exactly one surviving candidate.

- Positive sources (`xref_strings`, `xref_gvs`, `xref_signatures`, `xref_funcs`, `inline_alias`) are **intersected**; exclusions (`exclude_strings/gvs/funcs/signatures/callees`) subtract afterwards; `xref_floats` are post-intersection AND/OR filters (every `xref_floats` value must hit; any `exclude_floats` hit drops the candidate).
- `xref_signatures` follow the CS2 probe rule: after strings/gvs, if the current intersection is non-empty and ≤ 256 functions, keep only those whose **function body** contains the signature (`ida_bytes.find_bytes` in `[start, end)`). Otherwise fall back to a global `find_bytes` match-EA set. Collection order is strings → gvs → signatures → inline_alias → xref_funcs → vtable.
- `xref_strings` uses substring match unless prefixed `FULLMATCH:` (exact equality). A literal used inside the target function locates it directly; a literal used by a caller locates the caller (use that only as an `LLM_DECOMPILE` predecessor).
- Exactly one function must remain (`len(candidates) == 1`). A generated `func_sig` is kept only when `_find_unique_bytes` resolves uniquely to that function start; otherwise `func_sig` is dropped and basic `func_va` / `func_rva` / `func_size` metadata is still returned (CS2-aligned).

## The shared-prologue problem

Auto-generated signatures cap at `fixed < 24` / `len(tokens) < 64`. GoldSrc's `Sys_Error` (variadic, 1024-byte formatted buffer) starts with a `vsnprintf`-into-1024-buffer prologue byte-identical with the `Con_Printf`-family wrappers (`sub_1D2F9E0`, `sub_1DB95F0`, `sub_1DB9630`, `sub_1DBAAD0` on hl-3248; two lookalikes on cof-5936 share a 42-byte prologue and diverge ~110 tokens in). The string `"FATAL ERROR (shutting down): %s"` still uniquely anchors `Sys_Error` (1 candidate), but the capped `func_sig` matched 5 addresses → `_find_unique_bytes` returned None → preprocessor failed.

## The fix: func_sig_allow_across_function_boundary

Adding `func_sig_allow_across_function_boundary:true` to `GENERATE_YAML_DESIRED_FIELDS` alone only **tags** the emitted YAML — it did not change signature generation in the original code.

The real fix in `ida_analyze_util.py` extends the caps when the flag is set:

- Both `_signature` templates (`_FUNC_XREF_PY_EVAL_TEMPLATE` and `_INSPECT_FUNCTION_PY_EVAL`) now read a flag and raise `max_fixed` → 256 and `max_tokens` → 256 (defaults stay 24/64, so existing finders are unaffected).
- Flag plumbing: `_func_xref_spec_with_across(spec, flag)` adds `spec["allow_across_function_boundary"]=True` used by `preprocess_func_xrefs_via_mcp`; `_inspect_function_via_mcp(..., allow_across_function_boundary=...)` and `preprocess_func_sig_via_mcp` (which also honors `old_data.func_sig_allow_across_function_boundary`) thread it through the `ALLOW_ACROSS_FUNCTION_BOUNDARY_PLACEHOLDER`.
- `_inspect_function_via_mcp` regenerates + re-validates the signature internally (line ~1239), so a pre-seeded old YAML with a long unique sig alone did NOT help — the flag must lift the caps at generation time.

## Practical guidance

- When a Pattern A target shares a prologue with other functions, add `func_sig_allow_across_function_boundary:true` to its desired-fields entry; the emitted `func_sig` grows until unique and the YAML records `func_sig_allow_across_function_boundary: true`.
- Config symbol stays `category: func`; artifact identity is `func_name`. Do not put `func_sig_allow_across_function_boundary` in the config symbol — it belongs in the finder script's `generate_yaml_desired_fields`.

## Related

- [[reference_yaml_generation]] — LLM_DECOMPILE reference workflow (Patterns C/D/E).
- [[llm_decompile_runtime]] — LLM-derived signatures must uniquely match target VA; `func_sig_resolve_jmp_thunk` for near-jump chains.
- Worked anchor: `FULLMATCH:FATAL ERROR (shutting down): %s\n` → `Sys_Error`; regression RVAs hl-10210 hw.dll `0x21fc20` / hw.so `0xd4770`, svencoop-10257 hw.dll `0xabb050` / hw.so `0xaf0a0`.