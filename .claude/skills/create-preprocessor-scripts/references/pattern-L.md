# Pattern L — unique indirect vcall slot

Use for an abstract/interface vfunc whose stable evidence is a thin x86 thunk/caller containing
exactly one indirect vtable branch.

```python
from ida_preprocessor_scripts._indirect_vcall_target_common import (
    preprocess_indirect_vcall_target_skill,
)

SOURCE_FUNCTION_NAME = "{SOURCE_THUNK}"
TARGET_FUNCTION_NAME = "{INTERFACE_FUNC}"
VTABLE_CLASS = "{INTERFACE_CLASS}"

GENERATE_YAML_DESIRED_FIELDS = [
    (TARGET_FUNCTION_NAME, ["func_name", "vtable_name", "vfunc_offset", "vfunc_index"]),
]

async def preprocess_skill(session, skill_name, expected_outputs, old_yaml_map,
                           new_binary_dir, platform, image_base, debug=False):
    _ = skill_name, old_yaml_map, image_base
    return await preprocess_indirect_vcall_target_skill(
        session=session,
        expected_outputs=expected_outputs,
        new_binary_dir=new_binary_dir,
        platform=platform,
        source_yaml_stem=SOURCE_FUNCTION_NAME,
        target_name=TARGET_FUNCTION_NAME,
        vtable_name=VTABLE_CLASS,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        allowed_mnemonics=("call", "jmp"),
        expected_target_count=1,
        debug=debug,
    )
```

Rules:

- Source artifact supplies `func_va` and is the only required input.
- Scan accepts register-indirect `o_displ`/`o_phrase` calls and jumps.
- Offsets must be 4-byte aligned; index is `offset / 4`.
- Exactly one unique slot must remain.
- Output is slot-only: no `func_va`, `func_sig`, or `vfunc_sig`.
- A downstream Pattern F standard finder may consume the resulting index.
- Config category is `vfunc`.
