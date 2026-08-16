# Pattern D — ordinary function via LLM decompile

Use when a known predecessor directly calls or references a non-virtual target.

```python
LLM_DECOMPILE = [
    {
        "symbol_name": "{FUNC_NAME}",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": ["references/{gamever}/{module}/{PREDECESSOR}.{platform}.yaml"],
        "expected_result_sections": ["found_call"],
        "dependency_policy": {"{PREDECESSOR}.{platform}.yaml": "required"},
    },
]

GENERATE_YAML_DESIRED_FIELDS = [
    ("{FUNC_NAME}", ["func_name", "func_sig", "func_va", "func_rva", "func_size"]),
]
```

The script ABI includes `llm_config=None`. Forward `func_names`, `llm_decompile_specs`,
`llm_config`, and desired fields.

Rules:

- Prefer `found_call`; use `found_funcptr` only when the instruction contains one verifiable code pointer.
- `insn_va` must be in the current predecessor.
- The decoded call/code reference must have exactly one target.
- Config `expected_input` declares the predecessor according to `dependency_policy`.
- Config category is `func`; artifact identity is `func_name`.
