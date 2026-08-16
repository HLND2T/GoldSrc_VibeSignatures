# Pattern C — virtual function via LLM decompile

Use when a known predecessor exposes a vcall but deterministic xrefs cannot identify the target.
LLM output is only a proposal; IDA instruction/vtable validation is authoritative.

```python
LLM_DECOMPILE = [
    {
        "symbol_name": "{FUNC_NAME}",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": ["references/{gamever}/{module}/{PREDECESSOR}.{platform}.yaml"],
        "expected_result_sections": ["found_vcall"],
        "dependency_policy": {"{PREDECESSOR}.{platform}.yaml": "required"},
    },
]

FUNC_VTABLE_RELATIONS = [("{FUNC_NAME}", "{VTABLE_CLASS_OR_STEM}")]

GENERATE_YAML_DESIRED_FIELDS = [
    (
        "{FUNC_NAME}",
        [
            "func_name", "func_va", "func_rva", "func_size",
            "vfunc_sig", "vfunc_offset", "vfunc_index", "vtable_name",
        ],
    ),
]
```

`preprocess_skill` includes `llm_config=None` and forwards `llm_decompile_specs` and
`llm_config`.

Hard rules:

- `vfunc_sig` is mandatory for every Pattern C target.
- Include `func_va/func_rva/func_size` when another LLM finder will use this result as a predecessor.
- The returned `insn_va` must belong to the current predecessor function.
- The actual decoded x86 displacement must equal the proposed `vfunc_offset` and be 4-byte aligned.
- The selected slot must exist in the vtable and resolve to a real function body.
- Pure slot-only output belongs to Pattern F/L, not Pattern C.

Config `expected_input` includes the predecessor and artifact-backed vtable. Category is `vfunc`.
