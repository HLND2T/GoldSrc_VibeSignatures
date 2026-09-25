"""Small, conservative x86 value-flow model for interface dispatch.

The IDA adapter supplies decoded operands, CFG edges and verified stack deltas.
Unknown writes kill provenance. Joins retain bounded alternatives so guarded
devirtualization can merge a member load with a virtual getter's return value.
This is not an emulator: arithmetic unrelated to addresses is deliberately lost.
"""

from collections import deque
from itertools import product


MAX_ALTERNATIVES = 8
MAX_VALUE_DEPTH = 10
MAX_BLOCK_UPDATES = 4096
MAX_ARGUMENTS = 8
WORD_SIZE = 4


def alternatives(value):
    return value[1:] if value is not None and value[0] == "choice" else (value,)


def value_depth(value):
    if not isinstance(value, tuple):
        return 0
    return 1 + max((value_depth(part) for part in value[1:]), default=0)


def choice(*values):
    flattened = {part for value in values for part in alternatives(value)}
    if None in flattened or not flattened or len(flattened) > MAX_ALTERNATIVES:
        return None
    if any(value_depth(value) > MAX_VALUE_DEPTH for value in flattened):
        return None
    ordered = sorted(flattened, key=repr)
    return ordered[0] if len(ordered) == 1 else ("choice", *ordered)


def distribute(function, *values):
    return choice(*(function(*parts) for parts in product(*(alternatives(v) for v in values))))


def add_value(base, displacement):
    def add_one(value):
        if value is None:
            return None
        if value[0] in ("stack", "const"):
            total = value[1] + displacement
            return (value[0], total & 0xFFFFFFFF if value[0] == "const" else total)
        if not displacement:
            return value
        if value[0] == "address":
            return ("address", value[1], value[2] + displacement)
        return ("address", value, displacement)

    return distribute(add_one, base)


def load_value(address, state, static_loads):
    def load_one(value):
        if value is None:
            return None
        if ("modified", value) in state:
            return None
        if value[0] == "stack":
            return state.get(value)
        if value[0] == "const" and value[1] in static_loads:
            return ("const", static_loads[value[1]])
        if value[0] == "address":
            return ("load", value[1], value[2])
        return ("load", value, 0)

    return distribute(load_one, address)


def memory_address(operand, state):
    _, base, displacement, index, scale = operand[:5]
    address = state.get(base) if base else ("const", 0)
    if index:
        index_value = state.get(index)
        if index_value is None or index_value[0] != "const":
            return None
        displacement += index_value[1] * scale
    return add_value(address, displacement)


def operand_value(operand, state, static_loads):
    if operand[0] == "reg":
        if len(operand) > 3 and operand[3]:
            return None
        value = state.get(operand[1])
        return narrow(value, operand[2]) if len(operand) > 2 else value
    if operand[0] == "imm":
        return ("const", operand[1] & 0xFFFFFFFF)
    if operand[0] == "mem":
        value = load_value(memory_address(operand, state), state, static_loads)
        return narrow(value, operand[5]) if len(operand) > 5 else value
    return None


def narrow(value, width):
    if width == WORD_SIZE or value is None:
        return value
    if value[0] == "const":
        return ("const", value[1] & ((1 << (width * 8)) - 1))
    if value[0] == "narrow":
        return narrow(value[1], min(width, value[2]))
    return ("narrow", value, width)


def boolean_origin(value):
    # Boolean parameters/results may be read as AL or byte-sized stack slots.
    if value and value[0] == "narrow" and value[1] and value[1][0] in ("arg", "result"):
        return value[1]
    return value


def implicit_writes(mnemonic, operand_count):
    """Effects absent from IDA's explicit changed-operand flags."""
    mnemonic = mnemonic.split()[-1]
    if mnemonic in ("mul", "div", "idiv") or (mnemonic == "imul" and operand_count == 1):
        return ("eax", "edx")
    if mnemonic in ("cdq", "cwd"):
        return ("edx",)
    if mnemonic in ("cbw", "cwde", "xlat", "xlatb", "lahf"):
        return ("eax",)
    if mnemonic.startswith(("movs", "cmps")) and operand_count == 0:
        return ("esi", "edi", "ecx")
    if mnemonic.startswith(("lods", "outs")) and operand_count == 0:
        return ("eax", "esi", "ecx")
    if mnemonic.startswith(("stos", "scas", "ins")) and operand_count == 0:
        return ("edi", "ecx")
    if mnemonic in ("cpuid", "popa", "popad"):
        return ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp")
    if mnemonic in ("rdtsc", "rdmsr"):
        return ("eax", "edx")
    return ()


def virtual_targets(value):
    """Return (receiver, byte offset) only for a two-load vtable dispatch."""
    targets = []
    for part in alternatives(value):
        if part is None or part[0] != "load":
            return []
        table, offset = part[1:]
        if (
            table is None
            or table[0] != "load"
            or table[2] != 0
            or offset < 0
            or offset % WORD_SIZE
            or contains_narrow(table)
        ):
            return []
        targets.append((table[1], offset))
    return targets


def contains_narrow(value):
    return isinstance(value, tuple) and (value[0] == "narrow" or any(contains_narrow(part) for part in value[1:]))


def _join(states):
    keys = set().union(*(state.keys() for state in states))
    return {key: choice(*(state.get(key) for state in states)) for key in keys}


def _transfer(block, incoming, platform, static_loads, collect=False):
    state = incoming.copy()
    events = dict(calls=[], comparisons=[], branches=[], returns=[], stores=[])
    condition = None

    def write(operand, value, ea):
        if operand[0] == "reg":
            width = operand[2] if len(operand) > 2 else WORD_SIZE
            state[operand[1]] = None if len(operand) > 3 and operand[3] else choice(narrow(value, width))
        elif operand[0] == "mem":
            address = memory_address(operand, state)
            if address is not None and address[0] == "stack":
                width = operand[5] if len(operand) > 5 else WORD_SIZE
                for key in list(state):
                    if (
                        isinstance(key, tuple)
                        and key[0] == "stack"
                        and key != address
                        and key[1] < address[1] + width
                        and address[1] < key[1] + WORD_SIZE
                    ):
                        state[key] = None
                state[address] = choice(narrow(value, width))
            elif address is not None:
                state[("modified", address)] = ("const", 1)
            if collect:
                events["stores"].append(dict(ea=ea, address=address, value=value))

    for insn in block["insns"]:
        ea, mnemonic, operands = insn["ea"], insn["mnem"], insn["ops"]
        if mnemonic not in (
            "cmp",
            "test",
            "mov",
            "movzx",
            "movsx",
            "lea",
            "push",
            "pop",
            "nop",
            "leave",
            "jz",
            "jnz",
            "je",
            "jne",
            "jmp",
        ):
            condition = None
        correction = state.get("stack_correction", ("const", 0))
        if correction is None or correction[0] != "const":
            raise ValueError("inconsistent corrected stack depth")
        sp = insn["sp"] + correction[1]
        state["esp"] = ("stack", sp)
        read = lambda operand: operand_value(operand, state, static_loads)
        if mnemonic in ("mov", "movzx", "movsx") and len(operands) == 2:
            write(operands[0], read(operands[1]), ea)
            if operands[0][:2] == ("reg", "esp"):
                restored = state.get("esp")
                if restored and restored[0] == "stack":
                    state["stack_correction"] = ("const", restored[1] - insn["after"])
        elif mnemonic == "lea" and len(operands) == 2 and operands[1][0] == "mem":
            write(operands[0], memory_address(operands[1], state), ea)
        elif mnemonic == "push":
            state[("stack", sp - WORD_SIZE)] = read(operands[0])
        elif mnemonic == "pop":
            write(operands[0], state.get(("stack", sp)), ea)
        elif mnemonic in ("add", "sub") and len(operands) == 2:
            value = read(operands[1])
            result = (
                add_value(read(operands[0]), value[1] * (-1 if mnemonic == "sub" else 1))
                if value and value[0] == "const"
                else None
            )
            write(operands[0], result, ea)
        elif mnemonic == "xor" and len(operands) == 2 and operands[0] == operands[1]:
            write(operands[0], ("const", 0), ea)
        elif mnemonic == "and" and len(operands) == 2 and read(operands[1]) == ("const", 255):
            # Compilers mask an ABI boolean return before testing it.
            write(operands[0], narrow(read(operands[0]), 1), ea)
        elif mnemonic in ("cmp", "test") and len(operands) == 2:
            left, right = read(operands[0]), read(operands[1])
            condition = (
                boolean_origin(left) if (mnemonic == "test" and left == right) or right == ("const", 0) else None
            )
            if collect:
                events["comparisons"].append(dict(ea=ea, block=block["start"], values=[left, right]))
        elif mnemonic in ("jz", "jnz", "je", "jne"):
            target = insn.get("branch")
            other = [successor for successor in block["succs"] if successor != target]
            if collect and condition is not None and target in block["succs"] and len(other) == 1:
                zero, nonzero = (target, other[0]) if mnemonic in ("jz", "je") else (other[0], target)
                events["branches"].append(
                    dict(ea=ea, block=block["start"], condition=condition, zero=zero, nonzero=nonzero)
                )
        elif mnemonic == "call" or (mnemonic == "jmp" and insn.get("tail")):
            if insn.get("pc_reg"):
                state[insn["pc_reg"]] = ("const", insn["next_ea"])
                continue
            target = read(operands[0])
            tail = mnemonic == "jmp"
            stack_start = sp + (WORD_SIZE if tail else 0)
            stack_args = [state.get(("stack", stack_start + index * WORD_SIZE)) for index in range(MAX_ARGUMENTS)]
            inferred_purge = insn["after"] - insn["sp"]
            purged = insn.get("purge", max(0, inferred_purge))
            if platform == "windows":
                args = [state.get("ecx"), *(stack_args if tail else stack_args[: purged // WORD_SIZE])]
            else:
                args = stack_args
            if collect:
                events["calls"].append(
                    dict(
                        ea=ea,
                        block=block["start"],
                        target=target,
                        direct=insn.get("direct"),
                        args=[boolean_origin(v) for v in args],
                        stack_args=[boolean_origin(v) for v in stack_args],
                        this=state.get("ecx"),
                        tail=tail,
                    )
                )
            for value in stack_args:
                for escaped in alternatives(value):
                    if escaped and escaped[0] == "stack":
                        state[escaped] = None
            state["eax"] = ("result", ea)
            state["ecx"] = state["edx"] = None
            for offset in range(sp, sp + purged, WORD_SIZE):
                state.pop(("stack", offset), None)
            if "purge" in insn:
                state["stack_correction"] = ("const", correction[1] + purged - inferred_purge)
            condition = None
        elif mnemonic in ("ret", "retn"):
            if collect:
                events["returns"].append(dict(ea=ea, value=state.get("eax")))
        else:
            for register in insn.get("writes", []):
                state[register] = None
            for operand in insn.get("memory_writes", []):
                write(operand, None, ea)
        for register in implicit_writes(mnemonic, len(operands)):
            state[register] = None
    return state, events


def trace_function(blocks, entry, platform, static_loads=None):
    """Compute bounded reaching values and collect dispatch/branch observations."""
    graph = {block["start"]: block for block in blocks}
    if entry not in graph or platform not in ("windows", "linux"):
        raise ValueError("missing function entry or unsupported platform")
    static_loads = static_loads or {}
    initial = {
        ("stack", WORD_SIZE * (index + 1)): ("arg", index + (platform == "windows")) for index in range(MAX_ARGUMENTS)
    }
    initial["stack_correction"] = ("const", 0)
    if platform == "windows":
        initial["ecx"] = ("arg", 0)
    predecessors = {address: [] for address in graph}
    for block in blocks:
        for successor in block["succs"]:
            if successor in graph:
                predecessors[successor].append(block["start"])
    inputs, outputs = {}, {}
    work = deque([entry])
    updates = 0
    while work:
        address = work.popleft()
        sources = [outputs[pred] for pred in predecessors[address] if pred in outputs]
        if address == entry:
            sources.append(initial)
        if not sources:
            continue
        incoming = _join(sources)
        if inputs.get(address) == incoming:
            continue
        inputs[address] = incoming
        outputs[address], _ = _transfer(graph[address], incoming, platform, static_loads)
        updates += 1
        if updates > MAX_BLOCK_UPDATES:
            raise ValueError("interface dataflow did not converge")
        work.extend(successor for successor in graph[address]["succs"] if successor in graph)
    result = dict(calls=[], comparisons=[], branches=[], returns=[], stores=[])
    for address in sorted(inputs):
        _, events = _transfer(graph[address], inputs[address], platform, static_loads, collect=True)
        for key in result:
            result[key].extend(events[key])
    return result
