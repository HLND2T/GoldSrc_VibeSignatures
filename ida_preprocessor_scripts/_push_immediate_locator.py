"""IDA-side function intersections over decoded x86 immediate operands.

Injected into the owned worker so only candidate addresses cross MCP. The
imports stay inside the function to permit synthetic instruction tests.
"""


def wrap_locator_source(source):
    """Share helper globals and return JSON via py_eval's result, not stdout."""
    return "def main():\n ns = {}\n exec(" + repr(source) + ", ns)\n return ns['result']\nmain()"


def find_immediate_functions(required_values, function_starts=None, mnemonic=None):
    """Intersect decoded immediate values within each nominated function."""
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
    starts = idautils.Functions() if function_starts is None else function_starts
    for start in starts:
        found = set()
        # FuncItems includes the function's chunks; do not assume one range.
        for address in idautils.FuncItems(start):
            if not ida_bytes.is_code(ida_bytes.get_flags(address)):
                continue
            insn = idautils.DecodeInstruction(address)
            if insn is None:
                raise ValueError(f"instruction decode failed at {address:#x}")
            if mnemonic is None or insn.get_canon_mnem() == mnemonic:
                found.update(int(op.value) for op in insn.ops if op.type == ida_ua.o_imm)
        if required <= found:
            candidates.append(int(start))
    return candidates


def find_push_immediate_functions(required_values):
    """Return every function containing all required push-immediate values."""
    return find_immediate_functions(required_values, mnemonic="push")


def find_string_immediate_functions(required_values, literal, exclude_funcs=()):
    """Intersect an exact string's owners with immediates, excluding exact entries."""
    import ida_bytes
    import ida_funcs
    import idautils

    strings = [item for item in idautils.Strings() if str(item) == literal]
    if len(strings) != 1:
        raise ValueError(f"expected one exact string instance, found {len(strings)}")
    owners = set()
    for ref in idautils.XrefsTo(strings[0].ea):
        if not ida_bytes.is_code(ida_bytes.get_flags(ref.frm)):
            continue
        function = ida_funcs.get_func(ref.frm)
        if function is None:
            raise ValueError(f"string reference has no function owner at {ref.frm:#x}")
        owners.add(int(function.start_ea))
    for address in exclude_funcs:
        function = ida_funcs.get_func(address)
        if function is None or function.start_ea != address:
            raise ValueError(f"excluded address is not an exact function entry: {address:#x}")
        owners.discard(address)
    return find_immediate_functions(required_values, sorted(owners))
