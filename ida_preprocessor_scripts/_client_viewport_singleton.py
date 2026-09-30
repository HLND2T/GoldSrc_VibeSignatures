"""Small, pure proofs used by the client interface singleton locator."""

UINT32_MASK = 0xFFFFFFFF
X86_POINTER_BYTES = 4


def bounded_body(start, decode, limit, *, tail_target=None):
    """Decode a return-delimited body independently of IDA function ownership.

    A tail jump is allowed only to the independently proved constructor entry.
    The decoder must reject addresses outside the starting executable segment.
    """
    result = []
    cursor = start
    for _ in range(limit):
        item = decode(cursor)
        if item is None or item["ea"] != cursor or item["next_ea"] <= cursor:
            return None
        result.append(item)
        mnemonic = item["mnem"]
        if mnemonic in ("ret", "retn"):
            return result
        if mnemonic == "jmp" and tail_target is not None and item.get("direct") == tail_target:
            return result if not start <= tail_target < item["next_ea"] else None
        if mnemonic.startswith(("j", "loop", "int", "ret")) or mnemonic in ("ud2", "hlt"):
            return None
        cursor = item["next_ea"]
    return None


def linear_stack(instructions):
    """Assign local x86 stack depths; never borrow a merged owner's IDA SPD."""
    if not instructions:
        return None
    result, depth = [], 0
    for instruction in instructions:
        item = dict(instruction, sp=depth)
        mnemonic, operands = item["mnem"], item["ops"]
        destination = operands[0] if operands else ()
        if mnemonic in ("push", "pop"):
            width = item.get("stack_width", X86_POINTER_BYTES)
            if len(destination) > 2 and destination[0] == "reg":
                width = destination[2]
            elif len(destination) > 5 and destination[0] == "mem":
                width = destination[5]
            if not destination or width != X86_POINTER_BYTES:
                return None
            if mnemonic == "pop" and destination[:2] == ("reg", "esp"):
                return None
            depth += -X86_POINTER_BYTES if mnemonic == "push" else X86_POINTER_BYTES
        elif mnemonic in ("add", "sub") and destination[:2] == ("reg", "esp"):
            if len(destination) > 2 and destination[2] != X86_POINTER_BYTES:
                return None
            if len(operands) != 2 or operands[1][0] != "imm" or not isinstance(operands[1][1], int):
                return None
            depth += operands[1][1] * (-1 if mnemonic == "sub" else 1)
        elif mnemonic == "call":
            purge = item.get("purge")
            if not isinstance(purge, int) or purge < 0 or purge % X86_POINTER_BYTES:
                return None
            depth += purge
        elif (
            (destination[:2] == ("reg", "esp") and mnemonic not in ("cmp", "test"))
            or "esp" in item.get("writes", [])
            or mnemonic in ("enter", "leave")
            or mnemonic.startswith(("push", "pop"))
        ):
            return None
        item["after"] = depth
        result.append(item)
    return result


def constant_factory_return(instructions):
    """Evaluate a bounded straight-line factory, including MSVC's null conversion.

    NEG sets carry for a nonzero source; SBB reg,reg then produces its boolean
    mask. Keeping that carry proof rejects an otherwise unproven AND address.
    Calls, branches and unknown effects are deliberately unsupported.
    """
    registers = {}
    carry = None

    def read(operand):
        kind, value = operand[:2]
        return value if kind == "imm" and isinstance(value, int) else registers.get(value) if kind == "reg" else None

    for item in instructions:
        mnemonic, operands = item["mnem"], item["ops"]
        if mnemonic in ("ret", "retn"):
            return registers.get("eax")
        if mnemonic == "nop":
            continue
        if not operands or operands[0][0] != "reg":
            return None
        if any(op[0] == "reg" and len(op) > 2 and op[2] != X86_POINTER_BYTES for op in operands):
            return None
        destination = operands[0][1]
        value = None
        if mnemonic == "mov" and len(operands) == 2:
            value = read(operands[1])
        elif mnemonic == "neg" and len(operands) == 1:
            source = read(operands[0])
            carry = None if source is None else source != 0
            value = None if source is None else -source & UINT32_MASK
        elif mnemonic == "sbb" and len(operands) == 2 and operands[0] == operands[1]:
            value = None if carry is None else UINT32_MASK if carry else 0
        elif mnemonic == "and" and len(operands) == 2:
            left, right = read(operands[0]), read(operands[1])
            value = None if left is None or right is None else left & right
            carry = False
        elif mnemonic == "xor" and len(operands) == 2 and operands[0] == operands[1]:
            value, carry = 0, False
        else:
            return None
        registers[destination] = value
    return None


def unique_constructed_base(interface, primary_table, stores, secondary_offset):
    """Require paired complete-object/interface vptr installs and current RTTI.

    ``secondary_offset(table)`` supplies the displacement recovered from that
    binary's RTTI, or None when the table belongs to another class.
    """
    primary = {
        item["address"][1]
        for item in stores
        if item.get("width") == X86_POINTER_BYTES
        and item.get("address")
        and item["address"][0] == "const"
        and item.get("value") == ("const", primary_table)
    }
    offsets = {
        secondary_offset(item["value"][1])
        for item in stores
        if item.get("width") == X86_POINTER_BYTES
        and item.get("address") == ("const", interface)
        and item.get("value")
        and item["value"][0] == "const"
    }
    candidates = {base for base in primary if base <= interface and interface - base in offsets}
    return next(iter(candidates)) if len(candidates) == 1 else None
