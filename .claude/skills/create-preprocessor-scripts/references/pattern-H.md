# Pattern H — secondary/ordinal vtable

Use for multiple-inheritance secondary vtables under 32-bit MSVC or Itanium ABI.

```python
from pathlib import Path

from ida_analyze_util import write_vtable_yaml
from ida_preprocessor_scripts._ordinal_vtable_common import preprocess_ordinal_vtable_via_mcp

TARGET_CLASS_NAME = "{CLASS_NAME}"
TARGET_OUTPUT_STEM = "{CLASS_NAME}_vtable2"
WINDOWS_SYMBOL_ALIASES = ["{MSVC_MANGLED_SECONDARY_VTABLE}"]
LINUX_EXPECTED_OFFSET_TO_TOP = -4

async def preprocess_skill(session, skill_name, expected_outputs, old_yaml_map,
                           new_binary_dir, platform, image_base, debug=False):
    _ = skill_name, old_yaml_map, new_binary_dir
    filename = f"{TARGET_OUTPUT_STEM}.{platform}.yaml"
    outputs = [path for path in expected_outputs if Path(path).name == filename]
    if len(outputs) != 1:
        return False
    result = await preprocess_ordinal_vtable_via_mcp(
        session=session,
        class_name=TARGET_CLASS_NAME,
        ordinal=0,
        image_base=image_base,
        platform=platform,
        symbol_aliases=WINDOWS_SYMBOL_ALIASES if platform == "windows" else None,
        expected_offset_to_top=LINUX_EXPECTED_OFFSET_TO_TOP if platform == "linux" else None,
        debug=debug,
    )
    if not result:
        return False
    write_vtable_yaml(outputs[0], result)
    return True
```

Rules:

- `ordinal=0` is the first secondary table; increment for later secondary tables.
- Windows uses a verified MSVC mangled symbol/RTTI relationship.
- Linux uses the Itanium address point and a verified negative offset-to-top.
- All entries and table sizes use 4-byte pointers.
- Config category is `vtable`; artifact identity is `vtable_class`.
