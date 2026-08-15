---
name: get-vtable-index
description: |
  Find a function's vtable offset and index using IDA Pro MCP. Use this skill when you have a function address and need to determine its position in a vtable by iterating through vtable entries. GoldSrc x86 only: 4-byte vtable slots.
  Triggers: vtable index, vftable offset, virtual function table position, find function in vtable
---

# Get VTable Index (GoldSrc)

Find a function's position (offset and index) within a vtable by iterating through vtable entries. Applies to GoldSrc **PE32/I386** (Windows) and **ELF32/I386** (Linux) binaries only.

## Prerequisites

- Function address (from decompilation or xrefs)
- ClassName (to get vtable via `get-vtable-address` skill)
- platform (either `windows` or `linux`, depending on the binary we are analyzing)

## Method

### 1. Load vtable YAML and find function index:

   **ALWAYS** first check if `{ClassName}_vtable.{platform}.yaml` exists beside the binary, then search for the function in `vtable_entries`:

   ```python
   mcp__ida-pro-mcp__py_eval code="""
   import idaapi
   import yaml
   import os

   # === REQUIRED: Replace these values ===
   class_name = "<ClassName>"        # e.g., "CBasePlayer"
   func_addr = <FUNC_ADDRESS>        # Target function address to find
   # ======================================

   input_file = idaapi.get_input_file_path()
   dir_path = os.path.dirname(input_file)
   platform = 'windows' if input_file.endswith('.dll') else 'linux'

   yaml_path = os.path.join(dir_path, f"{class_name}_vtable.{platform}.yaml")

   if not os.path.exists(yaml_path):
       print(f"ERROR: Required file {class_name}_vtable.{platform}.yaml not found.")
       print(f"Expected path: {yaml_path}")
       print(f"Please run `/find-{class_name}_vtable` first to generate the vtable YAML file.")
   else:
       with open(yaml_path, 'r', encoding='utf-8') as f:
           data = yaml.safe_load(f)

       vtable_entries = data.get('vtable_entries', {})
       vtable_va = data.get('vtable_va')
       # GoldSrc x86: pointer size is always 4 bytes.
       ptr_size = 4

       for idx, entry in vtable_entries.items():
           # Handle both int and hex string formats
           i = int(idx) if isinstance(idx, str) else idx
           entry_addr = int(entry, 16) if isinstance(entry, str) else entry
           if entry_addr == func_addr:
               offset = i * ptr_size
               print(f"Found at vfunc_offset: {hex(offset)}, vfunc_index: {i}")
               print(f"vtable_va: {hex(vtable_va) if isinstance(vtable_va, int) else vtable_va}")
               break
       else:
           print(f"Function {hex(func_addr)} not found in {class_name} vtable entries!")
   """
   ```

   Replace:
   - `<ClassName>` with the target class name (e.g., `CBasePlayer`)
   - `<FUNC_ADDRESS>` with the target function address

   **IMPORTANT**: Use the function *entry* address. VTables store pointers to the function start; string xrefs often land in the middle of a function. If you only have an address inside the function, resolve the real entry first:
   ```python
   mcp__ida-pro-mcp__py_eval code="""
   import idaapi
   addr_inside_func = <ADDRESS_INSIDE_FUNCTION>
   f = idaapi.get_func(addr_inside_func)
   print(f"Function entry: {hex(f.start_ea)}" if f else "Not inside a function")
   """
   ```

### 2. Continue with the unfinished tasks

    If we are called by a task from a task list / parent SKILL, restore and continue with the unfinished tasks.

## Formulas (GoldSrc x86)

- `vfunc_offset = index × 4` (vtable slots are always 4 bytes on GoldSrc x86)
- `vfunc_index = offset / 4`, and is the index of the entry in `vtable_entries`.

Do **not** use `ptr_size = 8` (x86-64 Source2). GoldSrc is PE32/ELF32 I386 with 4-byte vfunc slots.
