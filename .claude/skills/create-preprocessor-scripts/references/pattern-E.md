# Pattern E — struct member via LLM decompile

Use when a known predecessor contains a stable access to a struct member.

```python
TARGET_STRUCT_MEMBER_NAMES = ["{STRUCT}_{MEMBER}"]

LLM_DECOMPILE = [
    {
        "symbol_name": "{STRUCT}_{MEMBER}",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": ["references/{gamever}/{module}/{PREDECESSOR}.{platform}.yaml"],
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
- Normally the returned offset must be present in the decoded x86 displacement operand.
- If an approved deterministic fallback proves that a nested member is only exposed through an out-of-line
  accessor, it may replay an immediate base-member reference with `offset_sig_ref_kind: immediate` and add
  the current binary's independently verified nested-member displacement via `offset_sig_addend`. Do not
  copy either value from a reference build or use an old output artifact as discovery evidence.
- `offset_sig_ref_kind` accepts only `displacement` (the default) or `immediate`; both it and
  `offset_sig_addend` require `offset_sig`.
- Optional `expected_size` must equal the LLM result and is only valid for struct members.
- Config declares the parent `category: struct` and the member `category: structmember` with
  `struct` and `member` fields.
- Artifact identity is `struct_name` + `member_name`; never generic `name`.
