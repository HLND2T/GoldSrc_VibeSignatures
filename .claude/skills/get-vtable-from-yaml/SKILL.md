---
name: get-vtable-from-yaml
description: Load vtable information from a pre-generated YAML file. Use this skill when you need to get vtable address and size for a class before analyzing virtual functions. This skill checks for existing vtable YAML files and errors out if not found, ensuring the vtable analysis has been done first.
---

# Get VTable from YAML (GoldSrc)

Load vtable information from the exact analyzer-bound `{class_name}_vtable.{platform}.yaml` artifact path. Select it from
the invocation prompt's artifact contract by basename; never derive a YAML path from the binary. A manual invocation must
provide the exact `bin_artifacts` path. Applies to GoldSrc **PE32/I386** (Windows) and **ELF32/I386** (Linux) binaries only.

## Parameters

- `class_name`: The class name to look up (e.g., `CBasePlayer`, `CBaseAnimating`, `CHud`)

## Method

### 1. Check and Load VTable YAML

Run the following code with the appropriate `class_name`:

```python
mcp__ida-pro-mcp__py_eval code="""
import idaapi
import os

class_name = "<CLASS_NAME>"  # Replace with actual class name

input_file = idaapi.get_input_file_path()
platform = 'windows' if input_file.endswith('.dll') else 'linux'

yaml_path = os.path.abspath(r"<EXACT_INPUT_ARTIFACT_PATH_FROM_INVOCATION_CONTRACT>")
if os.path.basename(yaml_path) != f"{class_name}_vtable.{platform}.yaml":
    raise ValueError(f"Artifact path does not match {class_name}_vtable.{platform}.yaml: {yaml_path}")

if os.path.exists(yaml_path):
    with open(yaml_path, 'r', encoding='utf-8') as f:
        print(f.read())
    print(f"YAML_EXISTS: True")
else:
    print(f"ERROR: Required file {class_name}_vtable.{platform}.yaml not found.")
"""
```

### 2. Handle Result

**If YAML exists** (`YAML_EXISTS: True`), extract these values from the output:
- `vtable_va`: The vtable virtual address (use as `<VTABLE_START>`)
- `vtable_rva`: The vtable relative virtual address
- `vtable_size`: The vtable size in bytes
- `vtable_numvfunc`: The valid vtable entry count (last valid index = count - 1)
- `vtable_entries`: An array of virtual functions starting from vtable[0].

Example YAML content:
```yaml
vtable_class: CBasePlayer
vtable_symbol: _ZTV10CBasePlayer + 0x8
vtable_va: 0x1028B9D8
vtable_rva: 0x28B9D8
vtable_size: 0x1f4
vtable_numvfunc: 125
vtable_entries:
  - 0x10240b20
  - 0x10240bc0
  - 0x10240bd0
```

**If YAML does NOT exist**, **ERROR OUT** and report to user:
```
ERROR: Required file {class_name}_vtable.{platform}.yaml not found.
Please run `/write-vtable-as-yaml` with class_name={class_name} first to generate the vtable YAML file.
```
Do NOT proceed with any remaining steps in the calling skill.

## Usage in Other Skills

When a skill needs vtable information, use this skill first:

```markdown
### 1. Get {ClassName} VTable Address

**ALWAYS** Use SKILL `/get-vtable-from-yaml` with `class_name={ClassName}`.

If the skill returns an error, stop and report to user.
Otherwise, extract `vtable_va`, `vtable_numvfunc` and `vtable_entries` for subsequent steps.
```

## Expected Output Values

| Field | Description | Example |
|-------|-------------|---------|
| `vtable_class` | Class name | `CBasePlayer` |
| `vtable_va` | Virtual address of vtable | `0x1028b9d8` |
| `vtable_rva` | Relative virtual address | `0x28b9d8` |
| `vtable_size` | Size in bytes | `0x1f4` |
| `vtable_numvfunc` | Number of virtual functions | `125` |
| `vtable_entries` | An array of virtual functions starting from vtable[0] | ... |

On GoldSrc x86 the entries are **4-byte pointers**, so `vfunc_offset = index * 4` and `vfunc_index = offset / 4`.
