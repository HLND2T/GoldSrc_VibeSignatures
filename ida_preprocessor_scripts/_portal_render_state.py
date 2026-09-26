"""Behavior proofs for portal shader state and legacy clip-plane setup."""

import copy

from ida_preprocessor_scripts._portal_layout import Trace, pointer, _dominates

WORD = 4
GL_CLIP_PLANE0 = 0x3000
LOCAL_WINDOW = 48
STATE_LIMIT = 12000
VECTOR_BYTES = 12
SETUP_INSTRUCTION_LIMIT = 400


class State(Trace):
    def value(self, op):
        if op.get("kind") == "global":
            return ("global", op["value"])
        if op.get("kind") == "reg" and op.get("size") == 1:
            return self.registers.get(op["reg"])
        return super().value(op)

    def step(self, insn):
        if insn.get("stack_offset") is not None:
            self.registers["esp"] = ("ptr", "stack", insn["stack_offset"])
        if insn["mnemonic"].startswith("j"):
            return
        if insn["mnemonic"] == "xor" and len(insn["operands"]) == 2 and insn["operands"][0] == insn["operands"][1]:
            self.registers[insn["operands"][0]["reg"]] = ("constant", 0)
            return
        if insn["mnemonic"] == "call" and "call_writes" in insn:
            for reg in insn["call_writes"]:
                self.registers.pop(reg, None)
            return
        super().step(insn)
        if insn["mnemonic"] == "call":
            self.registers["al"] = ("return-byte", insn["ea"])


def local_state(instructions, end, platform):
    start = end
    while start and end - start < LOCAL_WINDOW:
        previous = instructions[start - 1]
        if previous["mnemonic"].startswith(("j", "ret")) or previous["mnemonic"] == "call":
            break
        start -= 1
    state = State(platform)
    for item in instructions[start:end]:
        state.step(item)
    if instructions[end].get("stack_offset") is not None:
        state.registers["esp"] = ("ptr", "stack", instructions[end]["stack_offset"])
    return state


def paths(instructions, platform, start=0, state=None, limit=STATE_LIMIT):
    pending = [(start, state or State(platform, constructor=True))]
    seen = set()
    while pending:
        index, state = pending.pop()
        if not 0 <= index < len(instructions):
            continue
        key = (index, repr(state.registers), repr(state.memory))
        if key in seen:
            continue
        seen.add(key)
        if len(seen) > limit:
            raise ValueError("portal state walk exceeded its bound")
        item = instructions[index]
        if item.get("stack_offset") is not None:
            state.registers["esp"] = ("ptr", "stack", item["stack_offset"])
        yield index, item, state
        if item["mnemonic"].startswith("ret"):
            continue
        state.step(item)
        successors = item.get("successors", [index + 1])
        for target in successors:
            if target > index:  # These proofs never require a loop iteration.
                pending.append((target, copy.deepcopy(state)))


def shader_stores(instructions, platform):
    stores = {}
    for _, item, state in paths(instructions, platform):
        ops = item["operands"]
        if item["mnemonic"] != "mov" or len(ops) != 2:
            continue
        address = state.address(ops[0])
        if address and address[:2] == ("ptr", "this"):
            stores.setdefault((address[2], ops[0]["size"]), set()).add(state.value(ops[1]))
    return stores


def _branch_argument(instructions, index, state):
    # Tail jumps consume the caller's first argument above the return address.
    offset = WORD if instructions[index]["mnemonic"] == "jmp" else 0
    return state.memory.get((pointer(state.registers.get("esp"), offset), WORD))


def shader_toggle(instructions, init, platform, functions):
    """Recover guarded UseProgram(handle/0), including the split Linux reset helper."""
    result = []
    for call_index, call in enumerate(instructions):
        if call["mnemonic"] != "call" or call["operands"] != [{"kind": "func", "size": WORD, "value": init}]:
            continue
        state = local_state(instructions, call_index, platform)
        this = state.registers.get("ecx") if platform == "windows" else state.arguments(1)[0]
        if this is None:
            continue
        state.step(call)
        index = call_index + 1
        while index < len(instructions):
            cleanup = instructions[index]
            if cleanup["mnemonic"] != "add" or cleanup["operands"][0] != {"kind": "reg", "size": WORD, "reg": "esp"}:
                break
            state.step(cleanup)
            index += 1
        if index >= len(instructions):
            continue
        compare = instructions[index]
        ops = compare["operands"]
        if (
            compare["mnemonic"] != "cmp"
            or len(ops) != 2
            or ops[0].get("size") != 1
            or ops[1].get("kind") != "imm"
            or ops[1]["value"] != 0
        ):
            continue
        address = state.address(ops[0])
        root = pointer(this)
        if not address or not root or address[1] != root[1]:
            continue
        flag = address[2] - root[2]
        branch = index + 1
        while branch < len(instructions) and instructions[branch]["mnemonic"] == "pop":
            state.step(instructions[branch])
            branch += 1
        if branch >= len(instructions):
            continue
        guard = instructions[branch]
        if (
            guard["mnemonic"] not in {"jz", "je", "jnz", "jne"}
            or len(guard.get("successors", [])) != 2
            or branch + 1 not in guard["successors"]
        ):
            continue
        target = next(i for i in guard["successors"] if i != branch + 1)
        active = branch + 1 if guard["mnemonic"] in {"jz", "je"} else target
        inactive = target if active == branch + 1 else branch + 1
        # Stay inside the guarded region and stop at its merge with the zero path.
        pending = [(active, state)]
        seen = set()
        while pending:
            cursor, live = pending.pop()
            state_key = (cursor, repr(live.registers), repr(live.memory))
            if cursor == inactive or state_key in seen or not 0 <= cursor < len(instructions):
                continue
            seen.add(state_key)
            if len(seen) > LOCAL_WINDOW:
                raise ValueError("shader guard exceeds its bound")
            item = instructions[cursor]
            if item.get("stack_offset") is not None:
                live.registers["esp"] = ("ptr", "stack", item["stack_offset"])
            if item["mnemonic"] in {"call", "jmp"}:
                operand = item["operands"][0]
                if operand["kind"] == "func" and item["mnemonic"] == "call":
                    helper = functions.get(operand["value"], [])
                    for hi, hit, hs in paths(helper, platform):
                        if hit["mnemonic"] in {"call", "jmp"} and hit["operands"][0]["kind"] not in {"func", "api"}:
                            if _branch_argument(helper, hi, hs) == ("constant", 0):
                                result.append((flag, "disable", None, hs.value(hit["operands"][0]), compare["ea"]))
                    break
                if operand["kind"] not in {"func", "api"}:
                    argument = _branch_argument(instructions, cursor, live)
                    slot = live.value(operand)
                    if argument == ("constant", 0):
                        result.append((flag, "disable", None, slot, compare["ea"]))
                    elif argument and argument[0] == "load" and argument[2] == WORD and argument[1][1] == root[1]:
                        result.append((flag, "enable", argument[1][2] - root[2], slot, compare["ea"]))
                    break
            if item["mnemonic"].startswith("ret"):
                continue
            live.step(item)
            for successor in item.get("successors", [cursor + 1]):
                if successor > cursor:
                    pending.append((successor, copy.deepcopy(live)))
    return result


def recover_shader_member(init, draw, functions, platform):
    stores = shader_stores(functions[init], platform)
    toggles = []
    # Only the DrawPortals body and its actual direct callees can be active toggles.
    owners = {draw}
    owners.update(
        op["value"]
        for item in functions[draw]
        if item["mnemonic"] == "call"
        for op in item["operands"]
        if op["kind"] == "func" and op["value"] in functions
    )
    for owner in owners:
        toggles.extend(shader_toggle(functions[owner], init, platform, functions))
    flags = {item[0] for item in toggles}
    programs = {item[2] for item in toggles if item[1] == "enable"}
    slots = {item[3] for item in toggles}

    def has_global(value):
        return isinstance(value, tuple) and (value[0] == "global" or any(has_global(part) for part in value))

    if (
        len(flags) != 1
        or len(programs) != 1
        or len(slots) != 1
        or None in slots
        or not all(has_global(slot) for slot in slots)
        or {i[1] for i in toggles} != {"enable", "disable"}
    ):
        raise ValueError("active shader enable/disable evidence disagrees or is missing: %r" % (toggles,))
    flag, program = next(iter(flags)), next(iter(programs))
    values = stores.get((flag, 1), set())
    if flag < 0 or program == flag or (program, WORD) not in stores or ("constant", 0) not in values:
        raise ValueError("shader initialization does not write the guarded byte and program")
    if not any(value == ("constant", 1) or (value and value[0] == "return-byte") for value in values):
        raise ValueError("shader initialization has no availability assignment")
    return {"offset": flag, "size": 1, "instruction": toggles[0][4], "program": program}


def clip_setup(instructions, platform):
    """Require GL state setup with the same indexed clip enum and local equation."""
    calls = []
    for index, item in enumerate(instructions):
        if item["mnemonic"] != "call":
            continue
        state = local_state(instructions, index, platform)
        target = state.value(item["operands"][0])
        if target and target[0] == "api":
            calls.append((index, target[1], state.arguments(2)))
    for pos, (index, name, args) in enumerate(calls):
        if name != "glClipPlane" or pos == 0 or pos + 1 == len(calls):
            continue
        if calls[pos - 1][1] != "glLoadIdentity" or calls[pos + 1][1] != "glEnable":
            continue
        cap, equation = args
        if not cap or cap[0] != "ptr" or cap[2] != GL_CLIP_PLANE0:
            continue
        if not equation or equation[:2] != ("ptr", "stack"):
            continue
        # Across the call, the same callee-saved register must supply the cap.
        following = calls[pos + 1][0]
        live = local_state(instructions, index, platform)
        for item in instructions[index:following]:
            live.step(item)
        if live.arguments(1)[0] == cap:
            return True
    return False


def clip_call_arguments(instructions, target, platform):
    for index, item in enumerate(instructions):
        if item["mnemonic"] != "call" or item["operands"] != [{"kind": "func", "size": WORD, "value": target}]:
            continue
        state = local_state(instructions, index, platform)
        args = state.arguments(4 if platform == "windows" else 5)
        this = state.registers.get("ecx") if platform == "windows" else args.pop(0)
        plane_index, angles, view, plane = args
        # GCC retains viewangles = view + sizeof(Vector) across the preceding
        # DisableClipPlanes call. Recover only a dominating, unmodified alias.
        if angles and view and angles[:1] == view[:1] == ("ptr",) and angles[2] == view[2] == 0:
            aroot, vroot = angles[1], view[1]
            if isinstance(aroot, tuple) and isinstance(vroot, tuple) and aroot[0] == vroot[0] == "entry":
                for definition in range(index - 1, -1, -1):
                    item = instructions[definition]
                    ops = item["operands"]
                    if item["mnemonic"] == "lea" and ops == [
                        {"kind": "reg", "size": 4, "reg": aroot[1]},
                        {"kind": "mem", "size": WORD, "base": vroot[1], "disp": VECTOR_BYTES},
                    ]:
                        if _dominates(instructions, definition, index) and not any(
                            {aroot[1], vroot[1]} & set(x.get("writes", ()))
                            or (x["mnemonic"] == "call" and {aroot[1], vroot[1]} & {"eax", "ecx", "edx"})
                            for x in instructions[definition + 1 : index]
                        ):
                            angles = pointer(view, VECTOR_BYTES)
                        break
        if this and plane_index and plane and view and pointer(view, VECTOR_BYTES) == pointer(angles):
            return True
        if platform == "linux" and len(instructions) <= SETUP_INSTRUCTION_LIMIT:
            # Older GCC spills viewangles to a stack local before GL calls.
            # Walk each forward CFG path separately so a store on another
            # branch cannot supply this argument.
            for use, _, live in paths(instructions, platform):
                if use != index:
                    continue
                manager, number, angles, view, plane = live.arguments(5)
                if manager and number and plane and view and pointer(view, VECTOR_BYTES) == pointer(angles):
                    return True
    return False
