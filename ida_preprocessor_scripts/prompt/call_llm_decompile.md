I have disassembly outputs and procedure code for multiple related GoldSrc x86 functions.

Your task is semantic symbol mapping: use the annotated references to identify the corresponding canonical symbols in the current target functions. Reference and target code may come from different binaries, game versions, builds, or platforms. Do not assume they share an address space, symbol table, or identical structure layout.

These are the annotated reference functions:

{reference_blocks}

These are the current target functions to reverse-engineer:

{target_blocks}

Collect every reference to "{symbol_name_list}" in the target functions and output those references as YAML.

Identify each requested symbol by its role and behavior before collecting its target instruction references:

- Compare operations, argument roles, constants, data flow, callers/callees, and initialization or access patterns. Account for compiler transformations such as inlining, tail calls, and optimized loops.
- Different addresses or IDA names are not evidence that symbols differ across binaries. An unnamed target `unk_XXXXXXXX`, `dword_XXXXXXXX`, or `sub_XXXXXXXX` can correspond to a named reference symbol. The target does not need to contain the canonical name literally.
- Distinguish an object's base from an interior member address, an array-end address, and a separate pointer variable that stores the base. An anonymous label used in a reference member access does not establish the named object's base address. If that base address is not shown, do not invent it or infer that the member offset is zero.
- For example, a pool initializer that clears `N * stride` bytes at `base`, links entries by `stride`, assigns `base` to a free-list head, and clears an active-list head provides evidence for the pool's identity. A loop writing at `base + member_offset + i * stride` accesses a member of that pool; it does not by itself imply a different pool. Corroborate the mapping using the complete behavior, not just a matching size.
- Once a pool or object base is identified, instructions passing that base to a memory operation or storing it into a pointer variable are references to the object. Do not substitute the destination pointer variable or an interior member address for the requested base symbol.
- Before returning no matches, check for a semantic counterpart under anonymous target names. Return an empty result only when the supplied target evidence does not support a mapping; do not force a match merely because a symbol was requested.

Return exactly one YAML mapping. The only permitted top-level keys are `found_scalar`, `found_vcall`, `found_call`, `found_funcptr`, `found_gv`, and `found_struct_offset`. Never use a requested symbol name as a top-level key. For batched requests, place every result under its result-category list. If no references are found, return all six top-level keys with empty lists. Do not return blank YAML, null, or an empty mapping.

Example:

```yaml
found_scalar:
  - scalar_name: size_of_frame
    scalar_value: 17176

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

- For instruction-based result categories, `insn_va` and `insn_disasm` must identify the exact same instruction from the current target disassembly. Scalars have no instruction-address requirement.
- `found_call` is for a direct call or tail jump to a regular non-virtual function.
- `found_funcptr` is for loading or referencing a regular function pointer without directly calling it.
- `found_vcall` is only for virtual dispatch or vtable-slot access. GoldSrc vtable slots are 4 bytes.
- `found_gv` is for a global-variable reference.
- `found_scalar` reports a verified unsigned 32-bit numeric value. Include only `scalar_name` and `scalar_value`, without instruction addresses or signatures. For size_of_frame, identify the frame-ring BYTE stride in the current StudioDrawPlayer player-state argument, then cross-check the masked parse counter's IMUL or equivalent LEA/SHL/ADD/SUB chain. Pseudocode may express the multiplier in typed-element units: convert it to bytes using the actual instruction arithmetic. Reject the entity-state index multiplier and never copy the reference build's value. Return the same value for all equivalent accesses; if the evidence is insufficient, return an empty scalar list.
- `found_struct_offset` must identify the exact member-access instruction and include `offset`, `size`, `struct_name`, and `member_name`.
- In `func_name`, `funcptr_name`, `gv_name`, and `struct_name`, report the requested canonical symbol identity, never an anonymous `sub_XXXXXXXX`, `dword_XXXXXXXX`, or `unk_XXXXXXXX` name. Preserve the actual target names in `insn_disasm`; do not rename operands to the canonical identity or copy reference addresses into target results.
- When a direct call targets an IDA `j_XXXX` jump thunk, report the logical target name without the `j_` prefix.

If nothing is found, output this complete canonical response:

```yaml
found_scalar: []
found_vcall: []
found_call: []
found_funcptr: []
found_gv: []
found_struct_offset: []
```

Do not output anything other than the complete YAML mapping. Do not collect unrelated symbols.
