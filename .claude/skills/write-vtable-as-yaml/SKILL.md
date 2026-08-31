---
name: write-vtable-as-yaml
description: Write vtable analysis results to the exact analyzer-bound YAML artifact path using IDA Pro MCP. Use this skill after locating a vtable. GoldSrc x86 only: 4-byte vtable slots, Linux Itanium ABI skips 8 bytes of metadata.
---

# Write VTable as YAML (GoldSrc)

Persist vtable analysis results to the exact output path in the invocation prompt's artifact contract. Match the expected
basename and never derive the YAML path from the binary. Applies to GoldSrc **PE32/I386** (Windows) and **ELF32/I386**
(Linux) binaries only.

## Prerequisites

Before using this skill, you should have:
1. Located the target vtable address
2. Identified the class name for the vtable

## Required Parameters

| Parameter | Description | Example |
|-----------|-------------|---------|
| `vtable_class` | Class name for the vtable | `CBasePlayer` |
| `vtable_va` | Virtual address of the vtable | `0x1028B9D8` |

## Optional Parameters

| Parameter | Description | Example |
|-----------|-------------|---------|
| `vtable_symbol` | The IDA symbol name for the vtable | "??_7CBasePlayer@@6B@" |

## Method

```python
mcp__ida-pro-mcp__py_eval code="""
import idaapi
import ida_bytes
import ida_name
import os
import yaml

# === REQUIRED: Replace these values ===
vtable_class = "<vtable_class>"     # e.g., "CBasePlayer"
vtable_va = <vtable_va>             # e.g., 0x1028B9D8
# ======================================

# === OPTIONAL: Replace these values ===
vtable_symbol = "<vtable_symbol>"     # e.g., "??_7CBasePlayer@@6B@" or "_ZTV10CBasePlayer + 0x8" or "off_1028B9D8"
# ======================================

input_file = idaapi.get_input_file_path()

if input_file.endswith('.dll'):
    platform = 'windows'
    image_base = idaapi.get_imagebase()
else:
    platform = 'linux'
    image_base = 0x0

vtable_rva = vtable_va - image_base

# Handle Linux x86 vtables (skip Itanium ABI RTTI metadata).
# On GoldSrc x86 the metadata is TWO 4-byte pointers (offset-to-top + typeinfo),
# so the first vfunc pointer is at +0x8. This is NOT the x86-64 +0x10.
vtable_name = ida_name.get_name(vtable_va) or ""
if vtable_name.startswith("_ZTV"):
    vtable_va = vtable_va + 0x8
    vtable_rva = vtable_va - image_base

# GoldSrc x86: pointer size is always 4 bytes.
ptr_size = 4
vtable_entries = []

for i in range(1000):
    ptr_value = ida_bytes.get_dword(vtable_va + i * ptr_size)

    if ptr_value == 0 or ptr_value == 0xFFFFFFFF:
        break

    func = idaapi.get_func(ptr_value)
    if func is None:
        flags = ida_bytes.get_full_flags(ptr_value)
        if not ida_bytes.is_code(flags):
            break

    vtable_entries.append(ptr_value)

count = len(vtable_entries)
vtable_size = count * ptr_size

# Build YAML data structure
yaml_data = {
    'vtable_class': vtable_class,
    'vtable_symbol': vtable_symbol,
    'vtable_va': hex(vtable_va),
    'vtable_rva': hex(vtable_rva),
    'vtable_size': hex(vtable_size),
    'vtable_numvfunc': count,
    'vtable_entries': {i: hex(entry) for i, entry in enumerate(vtable_entries)}
}

yaml_path = os.path.abspath(r"<EXACT_OUTPUT_ARTIFACT_PATH_FROM_INVOCATION_CONTRACT>")
if os.path.basename(yaml_path) != f"{vtable_class}_vtable.{platform}.yaml":
    raise ValueError(f"Artifact path does not match {vtable_class}_vtable.{platform}.yaml: {yaml_path}")
os.makedirs(os.path.dirname(yaml_path), exist_ok=True)
with open(yaml_path, 'w', encoding='utf-8') as f:
    yaml.dump(yaml_data, f, default_flow_style=False, sort_keys=False, allow_unicode=True)
print(f"Written to: {yaml_path}")
"""
```

## Output File Naming Convention

The output YAML filename follows this pattern:
- `<vtable_class>_vtable.<platform>.yaml`

Examples:
- `hl.dll` → `CBasePlayer_vtable.windows.yaml`
- `hl.so` → `CBasePlayer_vtable.linux.yaml`

## Output YAML Format

`CBasePlayer_vtable.windows.yaml` - Example for CBasePlayer vtable on Windows:

```yaml
vtable_class: CBasePlayer
vtable_symbol: ??_7CBasePlayer@@6B@ # Symbol in IDA to CBasePlayer's vtable
vtable_va: 0x1028B9D8       # Virtual address - changes with game updates
vtable_rva: 0x28B9D8        # Relative virtual address (VA - image base) - changes with game updates
vtable_size: 0x1F4          # VTable size in bytes - changes with game updates
vtable_numvfunc: 125        # Number of virtual functions - changes with game updates
vtable_entries:             # Every virtual function starting from vtable[0]
  0: 0x10240B20             # vtable[0] - changes with game updates
  1: 0x10240FA0             # vtable[1] - changes with game updates
  2: 0x10240FF0             # vtable[2] - changes with game updates
```

`CBasePlayer_vtable.linux.yaml` - Example for CBasePlayer vtable on Linux (Itanium ABI, x86):

```yaml
vtable_class: CBasePlayer
vtable_symbol: _ZTV10CBasePlayer + 0x8 # Symbol in IDA to CBasePlayer's vtable
vtable_va: '0x2261dd8'       # Virtual address - changes with game updates
vtable_rva: '0x2261dd8'      # Relative virtual address (VA - image base) - changes with game updates
vtable_size: '0x1f4'         # VTable size in bytes - changes with game updates
vtable_numvfunc: 125         # Number of virtual functions - changes with game updates
vtable_entries:              # Every virtual function starting from vtable[0]
  0: '0x16ea780'             # vtable[0] - changes with game updates
  1: '0x16e9b50'             # vtable[1] - changes with game updates
  2: '0x16e3270'             # vtable[2] - changes with game updates
```

## Platform Detection

The skill automatically detects the platform based on file extension:
- `.dll` → Windows (uses `idaapi.get_imagebase()` for image base)
- `.so` → Linux (uses `0x0` as image base, skips RTTI metadata for `_ZTV` prefixed vtables)

## Linux VTable Handling (GoldSrc x86 — Itanium ABI, 4-byte pointers)

For Linux binaries, vtables with `_ZTV` prefix (mangled vtable names) have RTTI metadata at the beginning:
- Offset 0x00: offset to top (4 bytes)
- Offset 0x04: RTTI/typeinfo pointer (4 bytes)
- Offset 0x08: First virtual function pointer

The skill automatically skips this metadata when counting virtual functions. On GoldSrc x86 the skip is
**8 bytes** (`+0x8`); on x86-64 Source2 it would be 16 bytes (`+0x10`). Do not use the Source2 offset.

## Notes

- All values marked "changes with game updates" should be regenerated when analyzing new binary versions
- The YAML file is written only to the exact analyzer-bound artifact path, never beside the binary
- vtable_size is automatically calculated as `vtable_numvfunc * 4` (4-byte slots on x86)
- vtable_rva is automatically calculated as `vtable_va - image_base`
- GoldSrc artifact payloads must contain only category-specific identity (`vtable_class`) plus the data fields;
  never write generic `name`, `type`, or `kind`
