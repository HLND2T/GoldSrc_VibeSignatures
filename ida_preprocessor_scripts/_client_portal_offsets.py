"""Prove portal offsets from decoded x86 operands and local control flow."""

POINTER_SIZE = 4
PROLOGUE_INSTRUCTION_LIMIT = 40
PROLOGUE_STATE_LIMIT = 256
TEXTURE_INSTRUCTION_LIMIT = 160
TEXTURE_STATE_LIMIT = 2048
GL_TEXTURE_2D = 0x0DE1
VOLATILE_REGISTERS = ("eax", "ecx", "edx")
# These instructions have no hidden general-register outputs. Unsupported
# operations (MUL, string operations, etc.) must not preserve stale provenance.
EXPLICIT_EFFECT_MNEMONICS = {"mov", "lea", "add", "sub", "xor", "and", "or", "inc", "dec", "push", "cmp", "test", "nop"}


def _address(operand, registers):
    if operand.get("kind") != "mem":
        return None
    base = registers.get(operand["base"])
    if base is None or base[0] != "address":
        return None
    return ("address", base[1], base[2] + operand.get("disp", 0))


def _value(operand, registers, stack=None, platform=None):
    if operand.get("size") != POINTER_SIZE:
        return None
    kind = operand["kind"]
    if kind == "reg":
        return registers.get(operand["reg"])
    if kind == "imm":
        return ("constant", operand["value"])
    if kind == "api":
        return ("api", operand["name"])
    address = _address(operand, registers)
    if address is None:
        return None
    _, root, offset = address
    if root == "stack":
        if stack is not None and offset in stack:
            return stack[offset]
        if platform == "linux" and offset == POINTER_SIZE:
            return ("address", "manager", 0)
        return None
    return ("load", root, offset)


def _step_registers(instruction, registers, stack, platform):
    mnemonic, operands = instruction["mnemonic"], instruction["operands"]
    if mnemonic in {"mov", "lea"} and len(operands) == 2:
        destination, source = operands
        result = _address(source, registers) if mnemonic == "lea" else _value(source, registers, stack, platform)
        if destination["kind"] == "reg" and destination.get("size") == POINTER_SIZE:
            registers[destination["reg"]] = result
            return
        address = _address(destination, registers)
        if address and address[1] == "stack":
            stack[address[2]] = result if destination.get("size") == POINTER_SIZE else None
    elif mnemonic in {"add", "sub"} and len(operands) == 2:
        destination, source = operands
        before = _value(destination, registers)
        if before and before[0] == "address" and source["kind"] == "imm":
            registers[destination["reg"]] = (
                "address",
                before[1],
                before[2] + source["value"] * (1 if mnemonic == "add" else -1),
            )
            return
    elif mnemonic == "push" and len(operands) == 1:
        pointer = registers.get("esp")
        if pointer and pointer[0:2] == ("address", "stack"):
            stack[pointer[2] - POINTER_SIZE] = _value(operands[0], registers, stack, platform)
            registers["esp"] = ("address", "stack", pointer[2] - POINTER_SIZE)
            return
    if mnemonic == "call":
        for register in VOLATILE_REGISTERS:
            registers.pop(register, None)
    elif mnemonic not in EXPLICIT_EFFECT_MNEMONICS and not mnemonic.startswith("j"):
        registers.clear()
        stack.clear()
    for register in instruction.get("writes", ()):
        registers.pop(register, None)


def _vector_offsets(instructions, platform):
    registers = {"esp": ("address", "stack", 0)}
    if platform == "windows":
        registers["ecx"] = ("address", "manager", 0)
    candidates, visited = set(), set()
    pending = [(0, registers, {})]
    while pending:
        index, registers, stack = pending.pop()
        if index >= min(PROLOGUE_INSTRUCTION_LIMIT, len(instructions)):
            continue
        state = (index, tuple(sorted(registers.items())), tuple(sorted(stack.items())))
        if state in visited:
            continue
        visited.add(state)
        if len(visited) > PROLOGUE_STATE_LIMIT:
            raise ValueError("portal prologue control flow exceeds its bound")
        instruction = instructions[index]
        operands = instruction["operands"]
        if instruction["mnemonic"] == "cmp" and len(operands) == 2:
            values = [_value(op, registers, stack, platform) for op in operands]
            if all(value and value[:2] == ("load", "manager") for value in values):
                begin, end = sorted(value[2] for value in values)
                # Require the empty-vector guard and an actual pointer load from
                # begin on its fallthrough path, not merely adjacent field loads.
                following = instructions[index + 1 : index + 6]
                if (
                    end - begin == POINTER_SIZE
                    and following
                    and following[0]["mnemonic"] in {"jz", "je"}
                    and index + 2 in following[0].get("successors", ())
                ):
                    live = dict(registers)
                    for item in following[1:]:
                        ops = item["operands"]
                        if item["mnemonic"] == "mov" and len(ops) == 2:
                            source = ops[1]
                            if (
                                source.get("kind") == "mem"
                                and source.get("size") == POINTER_SIZE
                                and source.get("disp", 0) == 0
                                and live.get(source["base"]) == ("load", "manager", begin)
                            ):
                                candidates.add((begin, end))
                                break
                        if item["mnemonic"].startswith("j") or item["mnemonic"] == "call":
                            break
                        _step_registers(item, live, dict(stack), platform)
        _step_registers(instruction, registers, stack, platform)
        mnemonic = instruction["mnemonic"]
        if mnemonic.startswith("ret") or mnemonic.startswith("loop"):
            continue
        if mnemonic.startswith("j"):
            for target in instruction.get("successors", ()):
                if target > index:
                    pending.append((target, dict(registers), dict(stack)))
        else:
            pending.append((index + 1, registers, stack))
    if len(candidates) != 1:
        raise ValueError("portal vector evidence is missing or ambiguous")
    return next(iter(candidates))


def _texture_candidates(instructions, start, base, texture_offset):
    # Separate states preserve provenance through the active-texture success /
    # diagnostic branches. No register facts are borrowed across branch paths.
    pending = [(start + 1, {base: ("address", "portal", 0)}, [], False, False)]
    candidates = set()
    visited = set()
    remaining = TEXTURE_STATE_LIMIT
    limit = min(len(instructions), start + TEXTURE_INSTRUCTION_LIMIT)
    while pending:
        index, registers, pushes, generated, bound = pending.pop()
        while start < index < limit:
            state = (index, tuple(sorted(registers.items())), tuple(pushes), generated, bound)
            if state in visited:
                break
            visited.add(state)
            remaining -= 1
            if remaining < 0:
                raise ValueError("portal texture control flow exceeds its bound")
            instruction = instructions[index]
            mnemonic, operands = instruction["mnemonic"], instruction["operands"]
            if mnemonic.startswith("ret") or mnemonic.startswith("loop"):
                break
            if mnemonic.startswith("j"):
                if pushes:
                    break
                successors = instruction.get("successors", ())
                if not successors or any(target <= index for target in successors):
                    break
                for target in successors:
                    pending.append((target, dict(registers), [], generated, bound))
                break
            if mnemonic == "push":
                pushes.append(_value(operands[0], registers))
            elif mnemonic == "call":
                target = _value(operands[0], registers)
                api = target[1] if target and target[0] == "api" else None
                args = list(reversed(pushes))
                if api == "glGenTextures":
                    generated = args == [("constant", 1), ("address", "portal", texture_offset)]
                    bound = False
                elif api == "glBindTexture":
                    bound = generated and args == [("constant", GL_TEXTURE_2D), ("load", "portal", texture_offset)]
                elif api == "glTexImage2D":
                    if generated and bound and len(args) == 9 and args[0] == ("constant", GL_TEXTURE_2D):
                        width, height = args[3:5]
                        if (
                            width
                            and height
                            and width[:2] == height[:2] == ("load", "portal")
                            and width[2] == texture_offset + POINTER_SIZE
                            and height[2] == width[2] + POINTER_SIZE
                        ):
                            candidates.add((texture_offset, width[2], height[2]))
                    break
                elif generated and api != "glEnable":
                    # Unknown calls between allocation/binding/upload invalidate
                    # the GL-state proof even when they preserve CPU registers.
                    generated = bound = False
                pushes = []
            elif operands and operands[0].get("reg") == "esp":
                pushes = []
            _step_registers(instruction, registers, {}, "windows")
            index += 1
    return candidates


def recover_portal_offsets(instructions, platform):
    """Return only offsets proven from this function; reject conflicting evidence."""
    if platform not in {"windows", "linux"}:
        raise ValueError("unsupported portal platform")
    begin, end = _vector_offsets(instructions, platform)
    result = {"vector_begin": begin, "vector_end": end}
    if platform == "linux":
        return result
    candidates = set()
    for index, instruction in enumerate(instructions):
        operands = instruction["operands"]
        if instruction["mnemonic"] != "cmp" or len(operands) != 2:
            continue
        field, zero = operands
        if (
            field.get("kind") == "mem"
            and field.get("size") == POINTER_SIZE
            and field["base"] not in {"esp", "ebp"}
            and zero.get("kind") == "imm"
            and zero["value"] == 0
        ):
            # The texture guard takes the address of that exact member before
            # branching to allocation. Unrelated null checks are not roots.
            address_taken = False
            for following in instructions[index + 1 : index + 4]:
                ops = following["operands"]
                if (
                    following["mnemonic"] == "lea"
                    and len(ops) == 2
                    and ops[0].get("kind") == "reg"
                    and ops[0].get("size") == POINTER_SIZE
                    and ops[1].get("kind") == "mem"
                    and ops[1].get("base") == field["base"]
                    and ops[1].get("disp", 0) == field.get("disp", 0)
                ):
                    address_taken = True
                    break
                if following["mnemonic"].startswith("j") or field["base"] in following.get("writes", ()):
                    break
            if not address_taken:
                continue
            candidates.update(_texture_candidates(instructions, index, field["base"], field.get("disp", 0)))
    if len(candidates) != 1:
        raise ValueError("portal texture evidence is missing or ambiguous")
    texture, width, height = next(iter(candidates))
    result.update(texture_id=texture, texture_width=width, texture_height=height)
    return result
