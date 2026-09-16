"""IDA-side function intersection over decoded x86 push-immediate operands.

Injected into the owned worker so only candidate addresses cross MCP. The
imports stay inside the function to permit synthetic instruction tests.
"""


def find_push_immediate_functions(required_values):
    """Return every function containing all required push-immediate values."""
    import ida_bytes
    import ida_ida
    import ida_ua
    import idautils

    required = tuple(required_values)
    if not required or any(type(value) is not int or not 0 <= value <= 0xFFFFFFFF for value in required):
        raise ValueError("push-immediate locator requires nonempty uint32 values")
    if not ida_ida.inf_is_32bit_exactly() or ida_ida.inf_get_procname() != "metapc":
        raise ValueError("push-immediate locator requires x86-32")
    required = set(required)
    candidates = []
    for start in idautils.Functions():
        found = set()
        # FuncItems includes the function's chunks; do not assume one range.
        for address in idautils.FuncItems(start):
            if not ida_bytes.is_code(ida_bytes.get_flags(address)):
                continue
            insn = idautils.DecodeInstruction(address)
            if insn is None:
                raise ValueError(f"instruction decode failed at {address:#x}")
            if insn.get_canon_mnem() == "push" and insn.ops[0].type == ida_ua.o_imm:
                found.add(int(insn.ops[0].value))
        if required <= found:
            candidates.append(int(start))
    return candidates
