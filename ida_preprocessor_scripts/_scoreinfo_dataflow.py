"""Conservative x86 validation of ScoreInfo's zero-member frags store.

The registered handler reads a player byte followed by four shorts (frags,
deaths, class, team). Validate that protocol, follow the first short's value,
and require an unbiased player-index * family-stride destination. Addresses
and registers come entirely from the current function, never the reference.
Unsupported value flows and cyclic control flow fail closed.
"""

import re
from collections import deque

from ida_llm_decompile import _build_target_disasm_index

CS_PLAYER_STRIDE = 0x74
CZDS_PLAYER_STRIDE = 0x1C
_READ_SHORT_COUNT = 4
_HEADER_CALL_COUNT = 2 + _READ_SHORT_COUNT
_REGISTER_FAMILIES = (
    ("eax", "ax", "al", "ah"),
    ("ebx", "bx", "bl", "bh"),
    ("ecx", "cx", "cl", "ch"),
    ("edx", "dx", "dl", "dh"),
    ("esi", "si"),
    ("edi", "di"),
    ("ebp", "bp"),
    ("esp", "sp"),
)
_REGISTERS = {
    name: (family[0], 32 if i == 0 else 16 if i == 1 else 8)
    for family in _REGISTER_FAMILIES
    for i, name in enumerate(family)
}
_CONDITIONAL_JUMPS = frozenset(
    "ja jae jb jbe jc je jg jge jl jle jna jnae jnb jnbe jnc jne jng jnge jnl jnle jno jnp jns jnz jo jp jpe jpo js jz".split()
)


def _number(text):
    if re.fullmatch(r"[0-9a-f]+h", text):
        return int(text[:-1], 16)
    if re.fullmatch(r"(?:0x[0-9a-f]+|[0-9]+)", text):
        return int(text, 16 if text.startswith("0x") else 10)
    return None


def _value(text, registers):
    if text in _REGISTERS:
        name, width = _REGISTERS[text]
        value, known_width = registers.get(name, (None, 0))
        if width == 8 or width > known_width:
            return None
        # Truncating an already-scaled index loses the affine-address proof.
        if width == 16 and value is not None and value[1:] != (1, 0):
            return None
        return value
    number = _number(text)
    return None if number is None else ("", 0, number)


def _sum(left, right, sign=1):
    if left is None or right is None or (left[0] and right[0] and left[0] != right[0]):
        return None
    return (left[0] or right[0], left[1] + sign * right[1], left[2] + sign * right[2])


def _scale(value, factor):
    return None if value is None or factor is None else (value[0], value[1] * factor, value[2] * factor)


def _address_expression(text, registers):
    text = text.replace(" ", "").removeprefix("ds:")
    match = re.fullmatch(r"(0)?\[([^\]]+)\]", text)
    if not match:
        return None
    expression = match[2]
    terms = re.findall(r"([+-]?)([^+-]+)", expression)
    if "".join(sign + term for sign, term in terms) != expression:
        return None
    result = ("", 0, 0)
    for sign, term in terms:
        parts = term.split("*")
        if len(parts) > 2:
            return None
        value = _value(parts[0], registers)
        if len(parts) == 2:
            value = _scale(value, _number(parts[1]))
        result = _sum(result, value, -1 if sign == "-" else 1)
    return result


def _global_index(operand, registers):
    operand = re.sub(r"^word ptr\s+", "", operand).removeprefix("ds:")
    match = re.fullmatch(r"([a-z_?@$][\w?.@$]*)\[([^\]]+)\]", operand)
    if match is None or match[1].startswith(("byte_", "dword_")):
        return None
    return _address_expression(f"[{match[2]}]", registers)


def _write(registers, destination, value):
    name, width = _REGISTERS[destination]
    registers.pop(name, None)
    # Stack-pointer arithmetic/spills are outside this register-only proof.
    if name != "esp" and value is not None and width >= 16:
        registers[name] = (value, width)


def _transfer(mnemonic, operands, registers, read_role):
    registers = dict(registers)
    if mnemonic == "call":
        if read_role is None:
            return {}  # Do not carry message-field provenance into later UI calls.
        for name in ("eax", "ecx", "edx"):
            registers.pop(name, None)
        registers["eax"] = ((read_role, 1, 0), 32)
        return registers
    destination = operands[0] if operands else ""
    if mnemonic in _CONDITIONAL_JUMPS or mnemonic in {"jmp", "ret", "retn", "cmp", "test", "push", "nop"}:
        return registers
    if destination not in _REGISTERS:
        # Ordinary stores do not alter register provenance; unknown instructions
        # can have implicit writes and must not preserve it accidentally.
        return registers if mnemonic == "mov" else {}
    value = None
    if mnemonic in {"mov", "movzx", "movsx"} and len(operands) == 2:
        value = _value(operands[1], registers)
    elif _REGISTERS[destination][1] == 32:
        if mnemonic == "lea" and len(operands) == 2:
            value = _address_expression(operands[1], registers)
        elif mnemonic in {"add", "sub"} and len(operands) == 2:
            value = _sum(_value(destination, registers), _value(operands[1], registers), -1 if mnemonic == "sub" else 1)
        elif mnemonic == "imul" and len(operands) in {2, 3}:
            source = destination if len(operands) == 2 else operands[1]
            value = _scale(_value(source, registers), _number(operands[-1]))
        elif mnemonic == "shl" and len(operands) == 2:
            shift = _number(operands[1])
            value = _scale(
                _value(destination, registers), 1 << shift if shift is not None and 0 <= shift < 32 else None
            )
    if mnemonic in {"mul", "imul", "div", "idiv"} and len(operands) == 1:
        return {}
    if mnemonic not in {"mov", "movzx", "movsx", "lea", "add", "sub", "imul", "shl", "xor", "and", "or", "pop"}:
        return {}
    _write(registers, destination, value)
    return registers


def windows_frags_instruction_rule(disasm_code, stride):
    """Return an exact current-target rule only for one proven frags store."""
    indexed, _ = _build_target_disasm_index([disasm_code])
    instructions = {}
    for address, lines in indexed.items():
        lines = {line for line in lines if not line.endswith(":")}
        if len(lines) != 1:
            return None
        line = next(iter(lines))
        parts = line.lower().split(None, 1)
        instructions[address] = (line, parts[0], [op.strip() for op in parts[1].split(",")] if len(parts) > 1 else [])
    if not instructions or stride not in {CS_PLAYER_STRIDE, CZDS_PLAYER_STRIDE}:
        return None
    addresses = sorted(instructions)
    prefix_calls = []
    for address in addresses:
        _line, mnemonic, operands = instructions[address]
        if mnemonic.startswith("j") or mnemonic.startswith("ret"):
            break
        if mnemonic == "call":
            if len(operands) != 1 or operands[0] in _REGISTERS or not re.fullmatch(r"[\w?@$]+", operands[0]):
                return None
            prefix_calls.append((address, operands[0]))
    if len(prefix_calls) != _HEADER_CALL_COUNT:
        return None
    callees = [target for _address, target in prefix_calls]
    if len(set(callees[-_READ_SHORT_COUNT:])) != 1 or len(set(callees[:3])) != 3:
        return None
    roles = dict(
        zip((address for address, _target in prefix_calls), (None, "player", "frags", "deaths", "class", "team"))
    )

    successors = {}
    for index, address in enumerate(addresses):
        _line, mnemonic, operands = instructions[address]
        following = addresses[index + 1 : index + 2]
        if mnemonic in {"ret", "retn"}:
            following = []
        elif mnemonic == "jmp" or mnemonic in _CONDITIONAL_JUMPS:
            target = (
                re.fullmatch(r"(?:(?:short|near ptr) )?(?:loc_|0x)([0-9a-f]+)", operands[0])
                if len(operands) == 1
                else None
            )
            if target is None or int(target[1], 16) not in instructions:
                return None
            following = ([] if mnemonic == "jmp" else following) + [int(target[1], 16)]
        elif mnemonic.startswith("j") or mnemonic.startswith("loop"):
            return None
        successors[address] = set(following)
    reachable = set()
    pending = [addresses[0]]
    while pending:
        address = pending.pop()
        if address not in reachable:
            reachable.add(address)
            pending.extend(successors[address])
    predecessors = {address: set() for address in reachable}
    for address in reachable:
        for successor in successors[address]:
            predecessors[successor].add(address)
    degrees = {address: len(parents) for address, parents in predecessors.items()}
    pending = deque(address for address, degree in degrees.items() if degree == 0)
    states = {}
    candidates = []
    while pending:
        address = pending.popleft()
        incoming = [states[parent] for parent in predecessors[address]]
        registers = dict(incoming[0]) if incoming else {}
        for state in incoming[1:]:
            registers = {name: value for name, value in registers.items() if state.get(name) == value}
        line, mnemonic, operands = instructions[address]
        if mnemonic == "mov" and len(operands) == 2:
            source = operands[1]
            if source in _REGISTERS and _REGISTERS[source][1] == 16:
                if _value(source, registers) == ("frags", 1, 0) and _global_index(operands[0], registers) == (
                    "player",
                    stride,
                    0,
                ):
                    candidates.append(line)
        states[address] = _transfer(mnemonic, operands, registers, roles.get(address))
        for successor in successors[address]:
            degrees[successor] -= 1
            if degrees[successor] == 0:
                pending.append(successor)
    if len(states) != len(reachable) or len(candidates) != 1:
        return None
    instruction = candidates[0]
    return {
        "regex": r"(?i)" + r"\s+".join(re.escape(token) for token in instruction.split()),
        "text": (
            "Return only this current-target instruction, proven to store the first READ_SHORT's "
            f"frags value at player index * {stride:#x} with no member displacement: {instruction}. "
            "Reject all other member accesses, including additional entries alongside this store."
        ),
    }
