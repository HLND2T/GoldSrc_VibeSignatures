Identify the array base of "{symbol_name_list}" in the current ScoreInfo message handler.

Annotated reference:

{reference_blocks}

Current target:

{target_blocks}

Return exactly ONE found_gv entry: the 16-bit store of frags at array member offset zero.
The handler reads a player index with READ_BYTE, followed by four READ_SHORT calls for
frags, deaths, playerclass, and teamnumber. Follow the FIRST READ_SHORT result through
register copies to its indexed array store. Check the player-index data flow as well.
Compiler registers, addresses, and store ordering can differ from the reference.

The reference's frags member is at offset zero. Reject deaths, playerclass, teamnumber,
comparisons, loads, and interior-address arithmetic. Do not collect every array access.
Do not include any other found_gv entries even when they belong to the same array.
Do not copy reference addresses, registers, or anonymous IDA names into target results.

Return only a YAML mapping with the keys found_vcall, found_call, found_funcptr,
found_gv, and found_struct_offset. All lists except found_gv must be empty.
The found_gv entry must contain insn_va, insn_disasm, and gv_name. Use the exact current
target instruction text and address, and the requested canonical symbol as gv_name.
Write insn_va as a quoted 0x-prefixed hexadecimal string, without an IDA segment prefix.
For example, an instruction labeled .text:00401A40 must use insn_va: '0x00401A40'.
Keep insn_disasm as the instruction text alone, without its address or segment label.
If the target evidence cannot identify one zero-offset frags store, return all five lists empty.
