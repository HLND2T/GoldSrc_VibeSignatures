Identify the base of "{symbol_name_list}" in the current V_StartPitchDrift function.

Annotated reference:

{reference_blocks}

Current target:

{target_blocks}

Map the source operation g_pitchdrift.pitchvel = v_centerspeed->value to the target.
The pitchvel member is at offset zero and identifies the whole object's base.
Return exactly ONE found_gv entry for the MOVSS global store that performs this assignment.
Follow the floating-point value through register copies or stack transfers as needed.
Reject laststop, nodrift, driftmove, the v_centerspeed pointer, stack stores, and all loads.
Even the pitchvel load is excluded: use its assignment store as the single stable anchor.
If there is no unique matching store, return all five result lists empty.

Return only a YAML mapping with found_vcall, found_call, found_funcptr, found_gv,
and found_struct_offset. All lists except found_gv must be empty.
Each found_gv entry must contain insn_va, insn_disasm, and gv_name.
Use the requested canonical symbol as gv_name. Preserve the exact target instruction
text in insn_disasm without its address, segment label, or comments.
Write insn_va as a quoted 0x-prefixed hexadecimal string without an IDA segment prefix:
an instruction labeled .text:00401A40 must use insn_va: '0x00401A40'.
Do not copy reference addresses, registers, or anonymous names into target results.
