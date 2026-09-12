---
title: llm_decompile_runtime
type: note
permalink: goldsrc-vibesignatures/llm-decompile-runtime
---

# LLM_DECOMPILE Runtime

## Contract

- Finder opt-in: accept `llm_config=None`; pass normalized `LLM_DECOMPILE` specs and config input metadata into `preprocess_common_skill`.
- Response is canonical six-section YAML: `found_scalar`, `found_vcall`, `found_call`, `found_funcptr`, `found_gv`, `found_struct_offset`; failures return all six empty lists. `found_scalar` carries only scalar_name and uint32 scalar_value, validated against the finder's independently recovered current-binary expected_value; it has no instruction-address requirement.
- Every non-empty result must match requested identity/category. Instruction-based results additionally require an exact exported `insn_va + insn_disasm` pair; numeric scalars require agreement with independently verified dataflow. Multiple `instruction_rules` are alternatives (OR), not cumulative constraints.
- GoldSrc runtime is x86-only: 4-byte vtable slots; implicit memory operands such as `[eax]` / `[ecx]` represent displacement 0.

## Request lifecycle

- Validate reference/policy/config classification before deterministic fast paths so a successful fast path cannot hide an invalid LLM contract.
- Required dependency: exactly one `expected_input`, valid current artifact required. Optional dependency: exactly one `optional_input`; a missing/invalid current artifact skips only that reference/target pair.
- Batch unresolved targets only when request shape matches `(model, prompt path, active reference paths, temperature)`; a fast-path mapping is resolved only after vfunc/category enrichment and all required desired fields are present.
- Export target comments/chunks/pseudocode; validate instructions against all function chunk ranges, including tail/cold chunks.
- YAML/schema/semantic corrections and transient transport retries share one bounded retry budget. Only 429/5xx, OpenAI/httpx connection/timeout/rate-limit classes, and equivalent connection messages use exponential backoff.
- LLM-derived function and anchor signatures must uniquely match their target VA. `func_sig_resolve_jmp_thunk` follows bounded near-jump chains before signature generation.

## Reference/consumer invariants

- Reference YAML generation and annotation workflow: [[reference_yaml_generation]].
- Reference comments and Hex-Rays procedure are preserved; target comments are stripped before prompting to avoid leaking stale annotations.
- Instruction-based producers re-check the live IDA instruction, unique code/data target, displacement/size, target-function membership, and pointer size before emitting canonical symbol YAML. Scalar producers emit the independently verified uint32 directly; no address or signature is fabricated.

## Verification

- LLM tests mock text transport/batch results; never require a network request.
- Core gates: `tests.test_ida_llm_decompile`, `tests.test_ida_skill_preprocessor`, `tests.test_repository_contract`, then `tests/run_test_suite.py all`.
