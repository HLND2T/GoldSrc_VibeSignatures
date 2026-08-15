---
name: write-globalvar-as-yaml
description: Write global variable analysis results as YAML file beside the binary using IDA Pro MCP. Use this skill after completing global variable identification and signature generation to persist the results in a standardized YAML format.
---

# Write Global Variable IDA Analysis Output as YAML (GoldSrc)

Persist global variable analysis results to a YAML file beside the binary using IDA Pro MCP. Applies to GoldSrc **PE32/I386** (Windows) and **ELF32/I386** (Linux) binaries only.

## Prerequisites

Before using this skill, you should have:
1. Identified and renamed the target global variable
2. Generated a unique signature using `/generate-signature-for-globalvar`

## Required Parameters

| Parameter | Description | Example |
|-----------|-------------|---------|
| `gv_name` | Name of the global variable | `g_pGlobals` |
| `gv_addr` | Virtual address of the global variable | `0x1024A000` |
| `gv_sig` | Unique byte signature (must start at the GV-referencing instruction) | `A1 ?? ?? ?? ?? 85 C0 74 ?? 8B 0D ?? ?? ?? ??` |
| `gv_inst_length` | Length of the instruction in bytes | `5` |
| `gv_inst_disp` | Displacement offset within the instruction | `1` |
| `gv_sig_va` | Virtual address where the signature matches | `0x10244610` |

**Note:** `gv_inst_offset` is always 0 - the signature MUST start at the instruction that references the global variable.

## Method

```python
mcp__ida-pro-mcp__py_eval code="""
import idaapi
import os
import yaml

# === REQUIRED: Replace these values ===
gv_name = "<gv_name>"               # e.g., "g_pGlobals"
gv_addr = <gv_addr>                 # e.g., 0x1024A000
gv_sig = "<gv_sig>"                 # e.g., "A1 ?? ?? ?? ?? 85 C0 74 ?? 8B 0D ?? ?? ?? ??"
gv_sig_va = <gv_sig_va>             # e.g., 0x10244610 (virtual address where signature matches)
gv_inst_length = <gv_inst_length>   # e.g., 5 (instruction length in bytes)
gv_inst_disp = <gv_inst_disp>       # e.g., 1 (displacement offset within instruction)
# ======================================

# Fixed value - signature must start at the GV-referencing instruction
gv_inst_offset = 0

# Get binary path and determine platform
input_file = idaapi.get_input_file_path()
dir_path = os.path.dirname(input_file)

if input_file.endswith('.dll'):
    platform = 'windows'
    image_base = idaapi.get_imagebase()
else:
    platform = 'linux'
    image_base = 0x0

gv_rva = gv_addr - image_base

data = {
    'gv_name': gv_name,
    'gv_va': hex(gv_addr),
    'gv_rva': hex(gv_rva),
    'gv_sig': gv_sig,
    'gv_sig_va': hex(gv_sig_va),
    'gv_inst_offset': gv_inst_offset,
    'gv_inst_length': gv_inst_length,
    'gv_inst_disp': gv_inst_disp,
}

yaml_path = os.path.join(dir_path, f"{gv_name}.{platform}.yaml")
with open(yaml_path, 'w', encoding='utf-8') as f:
    yaml.dump(data, f, default_flow_style=False, sort_keys=False)
print(f"Written to: {yaml_path}")
"""
```

## Output File Naming Convention

The output YAML filename follows this pattern:
- `<gv_name>.<platform>.yaml`

Examples:
- `hw.dll` → `g_pGlobals.windows.yaml`
- `hw.so` → `g_pGlobals.linux.yaml`

## Output YAML Format

```yaml
gv_name: g_pGlobals
gv_va: 0x1024A000      # Global variable's virtual address - changes with game updates
gv_rva: 0x24A000        # Relative virtual address (VA - image base) - changes with game updates
gv_sig: A1 ?? ?? ?? ?? 85 C0 74 ?? 8B 0D ?? ?? ?? ??  # Unique byte signature (starts at GV-referencing instruction)
gv_sig_va: 0x10244610     # The virtual address that signature matches
gv_inst_offset: 0          # Always 0 - signature must start at the GV-referencing instruction
gv_inst_length: 5          # A1 XX XX XX XX = 5 bytes
gv_inst_disp:   1          # Displacement offset starts at position 1 (after A1)
```

## Platform Detection

The skill automatically detects the platform based on file extension:
- `.dll` → Windows (uses `idaapi.get_imagebase()` for image base)
- `.so` → Linux (uses `0x0` as image base)

## Notes

- All values marked "changes with game updates" should be regenerated when analyzing new binary versions
- The YAML file is written to the same directory as the input binary
- gv_rva is automatically calculated as `gv_va - image_base`
- GoldSrc artifact payloads must contain only category-specific identity (`gv_name`) plus the data fields;
  never write generic `name`, `type`, or `kind`
- On x86-32 the `gv_inst_disp` points at the 4-byte **absolute-address** displacement (the GV's address), not a
  RIP-relative offset; `gv_inst_length` is used only to skip past the instruction when scanning
