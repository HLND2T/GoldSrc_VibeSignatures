# Pattern E — struct member via LLM decompile

Use when a known predecessor contains a stable access to a struct member.

```python
TARGET_STRUCT_MEMBER_NAMES = ["{STRUCT}_{MEMBER}"]

LLM_DECOMPILE = [
    {
        "symbol_name": "{STRUCT}_{MEMBER}",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": ["references/{module}/{PREDECESSOR}.{platform}.yaml"],
        "expected_result_sections": ["found_struct_offset"],
        "dependency_policy": {"{PREDECESSOR}.{platform}.yaml": "required"},
        # "expected_size": 4,
    },
]

GENERATE_YAML_DESIRED_FIELDS = [
    (
        "{STRUCT}_{MEMBER}",
        ["struct_name", "member_name", "offset", "size?", "offset_sig", "offset_sig_disp"],
    ),
]
```

Reference annotations in both fields use:

```text
(structmember, struct=StructName, member=member_name)
```

Rules:

- Include `size` for a real memory read/write with a natural width.
- Omit/mark `size?` for `lea`, which computes an address but does not establish member size.
- The returned offset must be present in the decoded x86 displacement operand.
- Optional `expected_size` must equal the LLM result and is only valid for struct members.
- Config declares the parent `category: struct` and the member `category: structmember` with
  `struct` and `member` fields.
- Artifact identity is `struct_name` + `member_name`; never generic `name`.
