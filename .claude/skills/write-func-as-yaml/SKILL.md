---
name: write-func-as-yaml
description: Write function analysis results to the exact analyzer-bound YAML artifact path using IDA Pro MCP. Use this skill after completing function identification and signature generation. For virtual functions with known vtable index, use write-vfunc-as-yaml instead.
---

# Write Function IDA Analysis Output as YAML (GoldSrc)

Persist function analysis results to the exact output path in the invocation prompt's artifact contract. Match the
`<func_name>.<platform>.yaml` basename and never derive the YAML path from the input binary. Applies to GoldSrc
**PE32/I386** (Windows) and **ELF32/I386** (Linux) binaries only.

## Prerequisites

Before using this skill, you should have:
1. Identified and renamed the target function
2. Generated a unique signature using `/generate-signature-for-function`

## Required Parameters

| Parameter | Description | Example |
|-----------|-------------|---------|
| `func_name` | Name of the function | `R_RenderView` |
| `func_addr` | Virtual address of the function | `0x10244610` |
| `func_sig` | Unique byte signature | `55 8B EC F3 0F 10 05 ?? ?? ?? ?? 83 EC 14` |

## Method

```python
mcp__ida-pro-mcp__py_eval code="""
import idaapi
import os
import yaml

# === REQUIRED: Replace these values ===
func_name = "<func_name>"           # e.g., "R_RenderView"
func_addr = <func_addr>             # e.g., 0x10244610
func_sig = "<func_sig>"             # e.g., "55 8B EC F3 0F 10 05 ?? ?? ?? ?? 83 EC 14"
# ======================================

# Get function size
func = idaapi.get_func(func_addr)
func_size = func.size() if func else 0

# Get binary identity and determine platform
input_file = idaapi.get_input_file_path()

if input_file.endswith('.dll'):
    platform = 'windows'
    image_base = idaapi.get_imagebase()
else:
    platform = 'linux'
    image_base = 0x0

func_rva = func_addr - image_base

data = {
    'func_name': func_name,
    'func_va': hex(func_addr),
    'func_rva': hex(func_rva),
    'func_size': hex(func_size),
    'func_sig': func_sig,
}

yaml_path = os.path.abspath(r"<EXACT_OUTPUT_ARTIFACT_PATH_FROM_INVOCATION_CONTRACT>")
if os.path.basename(yaml_path) != f"{func_name}.{platform}.yaml":
    raise ValueError(f"Artifact path does not match {func_name}.{platform}.yaml: {yaml_path}")
os.makedirs(os.path.dirname(yaml_path), exist_ok=True)
with open(yaml_path, 'w', encoding='utf-8') as f:
    yaml.dump(data, f, default_flow_style=False, sort_keys=False)
print(f"Written to: {yaml_path}")
"""
```

## Output File Naming Convention

The output YAML filename follows this pattern:
- `<func_name>.<platform>.yaml`

Examples:
- `hw.dll` → `R_RenderView.windows.yaml`
- `hw.so` → `R_RenderView.linux.yaml`

## Output YAML Format

```yaml
func_name: R_RenderView
func_va: 0x10244610   # Virtual address - changes with game updates
func_rva: 0x244610     # Relative virtual address (VA - image base) - changes with game updates
func_size: 0x4DB       # Function size in bytes - changes with game updates
func_sig: 55 8B EC F3 0F 10 05 ?? ?? ?? ?? 83 EC 14  # Unique byte signature
```

## Platform Detection

The skill automatically detects the platform based on file extension:
- `.dll` → Windows (uses `idaapi.get_imagebase()` for image base)
- `.so` → Linux (uses `0x0` as image base)

## Notes

- All values marked "changes with game updates" should be regenerated when analyzing new binary versions
- The YAML file is written only to the exact analyzer-bound artifact path, never beside the binary
- func_size is automatically calculated from IDA's function analysis
- func_rva is automatically calculated as `func_va - image_base`
- GoldSrc artifact payloads must contain only category-specific identity (`func_name`) plus the data fields;
  never write generic `name`, `type`, or `kind`
- For virtual functions with vtable information, use `/write-vfunc-as-yaml` instead
