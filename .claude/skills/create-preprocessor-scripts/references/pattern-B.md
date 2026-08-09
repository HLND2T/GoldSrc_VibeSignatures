# Pattern B — virtual function via xrefs

Pattern B is Pattern A plus vtable membership.

```python
FUNC_VTABLE_RELATIONS = [("{FUNC_NAME}", "{VTABLE_CLASS_OR_ARTIFACT_STEM}")]

GENERATE_YAML_DESIRED_FIELDS = [
    (
        "{FUNC_NAME}",
        [
            "func_name", "func_va", "func_rva", "func_size", "func_sig",
            "vtable_name", "vfunc_offset", "vfunc_index",
        ],
    ),
]
```

Pass `func_names`, `func_xrefs`, `func_vtable_relations`, and desired fields to
`preprocess_common_skill`.

Rules:

- If config consumes `{Class}_vtable.{platform}.yaml`, use that artifact stem in the relation.
- Bare class names trigger live 32-bit MSVC/Itanium vtable discovery.
- The located function must appear exactly once in the selected vtable.
- `vfunc_offset` is `vfunc_index * 4`, never `* 8`.
- Config category is `vfunc`; artifact identity remains `func_name`.

Checklist:

- [ ] Vtable artifact is declared as `expected_input` when artifact-backed.
- [ ] Vtable field set is complete.
- [ ] No LLM config.
