# Pattern A — ordinary function via xrefs

Use for a non-virtual function discovered from one or more positive xref sources.

```python
from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = ["{FUNC_NAME}"]

FUNC_XREFS = [
    {
        "func_name": "{FUNC_NAME}",
        "xref_strings": ["{XREF_STRING}"],
        "xref_gvs": [],
        "xref_signatures": [],
        "xref_funcs": [],
        "exclude_funcs": [],
        "exclude_strings": [],
        "exclude_gvs": [],
        "exclude_signatures": [],
    },
]

GENERATE_YAML_DESIRED_FIELDS = [
    ("{FUNC_NAME}", ["func_name", "func_sig", "func_va", "func_rva", "func_size"]),
]

async def preprocess_skill(session, skill_name, expected_outputs, old_yaml_map,
                           new_binary_dir, platform, image_base, debug=False):
    _ = skill_name
    return await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=old_yaml_map,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_names=TARGET_FUNCTION_NAMES,
        func_xrefs=FUNC_XREFS,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )
```

Rules:

- Use `FULLMATCH:` for short/generic strings.
- Platform-specific strings may use separate Windows/Linux specs selected in `preprocess_skill`.
- `xref_gvs` accepts current artifact stems (including `../engine/X`) or explicit `0x...` addresses.
- `xref_funcs` requires the callee artifact in `expected_input` so its current `func_va` is known.
- All positive sources intersect; exclusions subtract; exactly one function and one generated signature must remain.
- Config category is `func`; artifact identity is `func_name`.

Checklist:

- [ ] No vtable relation or LLM config.
- [ ] Desired fields contain `func_name` and the required function metadata.
- [ ] Production Windows/Linux signatures are unique.
