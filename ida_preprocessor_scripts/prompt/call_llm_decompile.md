I have disassembly outputs and procedure code for multiple related GoldSrc x86 functions.

These are the annotated reference functions:

{reference_blocks}

These are the current target functions to reverse-engineer:

{target_blocks}

Collect every reference to "{symbol_name_list}" in the target functions and output those references as YAML.

Return exactly one YAML mapping. The only permitted top-level keys are `found_vcall`, `found_call`, `found_funcptr`, `found_gv`, and `found_struct_offset`. Never use a requested symbol name as a top-level key. For batched requests, place every result under its result-category list. If no references are found, return all five top-level keys with empty lists. Do not return blank YAML, null, or an empty mapping.

Example:

```yaml
found_vcall:
  - insn_va: '0x00401710'
    insn_disasm: call dword ptr [eax+14h]
    vfunc_offset: '0x14'
    func_name: VirtualTarget

found_call:
  - insn_va: '0x00401820'
    insn_disasm: call sub_00403000
    func_name: DirectTarget

  - insn_va: '0x00401880'
    insn_disasm: call j_UtilityTarget
    func_name: UtilityTarget

found_funcptr:
  - insn_va: '0x00401930'
    insn_disasm: lea edx, sub_00404000
    funcptr_name: CallbackTarget

found_gv:
  - insn_va: '0x00401A40'
    insn_disasm: mov eax, ds:dword_00506000
    gv_name: g_Target

found_struct_offset:
  - insn_va: '0x00401B50'
    insn_disasm: mov eax, [ecx+20h]
    offset: '0x20'
    size: 4
    struct_name: TargetStruct
    member_name: member
```

Rules:

- `insn_va` and `insn_disasm` must identify the exact same instruction from the current target disassembly.
- `found_call` is for a direct call or tail jump to a regular non-virtual function.
- `found_funcptr` is for loading or referencing a regular function pointer without directly calling it.
- `found_vcall` is only for virtual dispatch or vtable-slot access. GoldSrc vtable slots are 4 bytes.
- `found_gv` is for a global-variable reference.
- `found_struct_offset` must identify the exact member-access instruction and include `offset`, `size`, `struct_name`, and `member_name`.
- Report the requested canonical symbol identity, never an anonymous `sub_XXXXXXXX`, `dword_XXXXXXXX`, or `unk_XXXXXXXX` name.
- When a direct call targets an IDA `j_XXXX` jump thunk, report the logical target name without the `j_` prefix.

If nothing is found, output this complete canonical response:

```yaml
found_vcall: []
found_call: []
found_funcptr: []
found_gv: []
found_struct_offset: []
```

Do not output anything other than the complete YAML mapping. Do not collect unrelated symbols.
