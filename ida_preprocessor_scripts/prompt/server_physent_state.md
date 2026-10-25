Map the requested global symbols {symbol_name_list} from the annotated references
to the current target's server area walker. Use actual current-target x86 dataflow.

Reference functions:
{reference_blocks}

Current target functions:
{target_blocks}

Return ONE resolvable address-carrier instruction for each requested global:
- pmove: address of the pointer variable whose current value owns the three PM lists.
- pr_strings: address of the pointer variable added to an entity's classname index.
- svs_maxclients: int field guarding entity numbers and unlag. For an absolute
  field access, return that instruction. If accessed indirectly, return the LEA
  materializing the enclosing server-static object immediately before the field
  load; the finder decodes and adds the following instruction's field offset.
- sv_unlag_value: address of the float value field tested for zero, not the enclosing cvar base.
- truepositions: base of the adjusted-position ARRAY, not an interior vector or a loaded active flag.

Prefer an absolute-address operand, a GOT address load, or a PIC LEA with only the
GOT base register. Do not return an access through a loaded pointer such as
mov eax,[eax+8], or an indexed array-element instruction with a variable index.
Trace that access back to the instruction materializing the object's base.
Do not copy reference addresses, guess layouts, or rewrite the target disassembly.

Return exactly the six YAML keys below, without prose. Only found_gv may be nonempty.
Each entry needs gv_name (the requested identity), insn_va and the exact target
insn_disasm. If evidence is insufficient, omit that symbol's entry.

found_scalar: []
found_vcall: []
found_call: []
found_funcptr: []
found_gv: []
found_struct_offset: []
