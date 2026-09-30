"""Small, pure proofs used by the client interface singleton locator."""

UINT32_MASK = 0xFFFFFFFF
X86_POINTER_BYTES = 4


def constant_factory_return(instructions):
    """Evaluate a bounded straight-line factory, including MSVC's null conversion.

    NEG sets carry for a nonzero source; SBB reg,reg then produces its boolean
    mask. Keeping that carry proof rejects an otherwise unproven AND address.
    Calls, branches and unknown effects are deliberately unsupported.
    """
    registers = {}
    carry = None

    def read(operand):
        kind, value = operand
        return value if kind == "imm" and isinstance(value, int) else registers.get(value) if kind == "reg" else None

    for item in instructions:
        mnemonic, operands = item["mnem"], item["ops"]
        if mnemonic in ("ret", "retn"):
            return registers.get("eax")
        if mnemonic == "nop":
            continue
        if not operands or operands[0][0] != "reg":
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
