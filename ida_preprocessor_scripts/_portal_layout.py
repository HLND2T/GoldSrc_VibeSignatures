"""Small, conservative x86 traces for portal constructor and call arguments."""

WORD = 4
VECTOR_BYTES = 12
TRACE_LIMIT = 400
GPRS = ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")
GL_TEXTURE_2D = 0xDE1


def pointer(value, displacement=0):
    if value is None:
        return None
    if value[0] == "ptr":
        return ("ptr", value[1], value[2] + displacement)
    return ("ptr", value, displacement)


class Trace:
    def __init__(self, platform, *, constructor=False):
        self.platform = platform
        self.registers = {r: ("ptr", ("entry", r), 0) for r in GPRS}
        self.registers["esp"] = ("ptr", "stack", 0)
        self.memory = {}
        self.stores = []
        self.constructor = constructor
        if constructor and platform == "windows":
            self.registers["ecx"] = ("ptr", "this", 0)

    def address(self, op):
        if op.get("kind") == "mem":
            return pointer(self.registers.get(op["base"]), op.get("disp", 0))

    def value(self, op):
        kind = op.get("kind")
        if kind == "reg":
            return self.registers.get(op["reg"]) if op.get("size") in (4, 8, 16) else None
        if kind == "imm":
            return ("constant", op["value"])
        if kind == "api":
            return ("api", op["name"])
        if kind == "func":
            return ("func", op["value"])
        address = self.address(op)
        if address is None:
            return None
        size = op.get("size")
        if address[1] == "stack":
            if (address, size) in self.memory:
                return self.memory[address, size]
            offset = address[2]
            if self.constructor and size == WORD and offset >= WORD and offset % WORD == 0:
                if self.platform == "linux" and offset == WORD:
                    return ("ptr", "this", 0)
                return ("ptr", ("argument", offset), 0)
        return ("load", address, size)

    def arguments(self, count):
        esp = self.registers.get("esp")
        return [self.memory.get((pointer(esp, WORD * i), WORD)) for i in range(count)]

    def step(self, insn):
        m, ops = insn["mnemonic"], insn["operands"]
        if m == "rep_movsd":
            source, destination = self.registers.get("esi"), self.registers.get("edi")
            if self.registers.get("ecx") == ("constant", VECTOR_BYTES // WORD) and source and destination:
                for offset in range(0, VECTOR_BYTES, WORD):
                    self.memory[pointer(destination, offset), WORD] = ("load", pointer(source, offset), WORD)
                self.registers["esi"] = pointer(source, VECTOR_BYTES)
                self.registers["edi"] = pointer(destination, VECTOR_BYTES)
                self.registers["ecx"] = ("constant", 0)
            else:
                self.registers.clear()
                self.memory.clear()
            return
        if m in {"mov", "movq", "movss", "movsd", "movaps", "movups", "movdqu", "movdqa", "lea"} and len(ops) == 2:
            dst, src = ops
            value = self.address(src) if m == "lea" else self.value(src)
            if dst.get("kind") == "reg" and dst.get("size") in (4, 8, 16):
                self.registers[dst["reg"]] = value
                return
            address = self.address(dst)
            if address is not None:
                size = dst.get("size", 0)
                # Invalidate overlapping writes, including partial stack stores.
                for key in list(self.memory):
                    old, width = key
                    if old[1] == address[1] and old[2] < address[2] + size and address[2] < old[2] + width:
                        del self.memory[key]
                self.memory[address, size] = value
                self.stores.append((address, size, value))
        elif m == "push":
            value = self.value(ops[0])
            self.registers["esp"] = pointer(self.registers.get("esp"), -WORD)
            if self.registers["esp"] is not None:
                self.memory[self.registers["esp"], WORD] = value
            return
        elif m == "pop" and ops and ops[0].get("kind") == "reg":
            esp = self.registers.get("esp")
            self.registers[ops[0]["reg"]] = self.memory.get((esp, WORD))
            self.registers["esp"] = pointer(esp, WORD)
            return
        elif m in {"add", "sub"} and len(ops) == 2 and ops[0].get("kind") == "reg" and ops[1].get("kind") == "imm":
            reg = ops[0]["reg"]
            before = self.registers.get(reg)
            self.registers[reg] = (
                pointer(before, ops[1]["value"] * (1 if m == "add" else -1))
                if before and (before[0] == "ptr" or (before[0] == "load" and before[2] == WORD))
                else None
            )
            return
        elif m == "call":
            for reg in ("eax", "ecx", "edx", *(f"xmm{i}" for i in range(8))):
                self.registers.pop(reg, None)
            if insn.get("stack_delta"):
                self.registers["esp"] = pointer(self.registers.get("esp"), insn["stack_delta"])
        elif m not in {
            "cmp",
            "test",
            "nop",
            "lfence",
            "fld",
            "fldz",
            "fld1",
            "fst",
            "fstp",
            "add",
            "sub",
            "xor",
            "and",
            "or",
            "sar",
            "shr",
            "shl",
            "inc",
            "dec",
            "movzx",
            "movsx",
            "cmovz",
            "cmovnz",
        }:
            self.registers.clear()
            self.memory.clear()
        for reg in insn.get("writes", ()):
            self.registers.pop(reg, None)
        if m not in {"mov", "movq", "movss", "movsd", "movaps", "movups", "movdqu", "movdqa", "lea"}:
            for op in insn.get("memory_writes", ()):
                address = self.address(op)
                if address is None:
                    continue
                for key in list(self.memory):
                    old, width = key
                    if old[1] == address[1] and old[2] < address[2] + op["size"] and address[2] < old[2] + width:
                        del self.memory[key]


def constructor_offsets(instructions, platform):
    """Prove three vec3 copies from constructor inputs into the same this object."""
    trace = Trace(platform, constructor=True)
    for insn in instructions[:TRACE_LIMIT]:
        if insn["mnemonic"].startswith(("j", "ret")) or insn["mnemonic"] == "pop":
            break
        trace.step(insn)
    copies = {}
    for (address, size), value in trace.memory.items():
        if address[1] != "this" or not value or value[0] != "load" or value[2] != size:
            continue
        source = value[1]
        if not isinstance(source[1], tuple) or source[1][0] != "argument":
            continue
        if size not in (WORD, 2 * WORD):
            continue
        group = copies.setdefault(source[1][1], {})
        for byte in range(size):
            group[source[2] + byte] = address[2] + byte
    first_argument = 2 * WORD if platform == "windows" else 3 * WORD
    offsets = []
    for argument in range(first_argument, first_argument + 3 * WORD, WORD):
        mapping = copies.get(argument, {})
        if set(mapping) != set(range(VECTOR_BYTES)):
            raise ValueError("constructor is missing a complete vec3 argument copy")
        start = mapping[0]
        if [mapping[i] for i in range(VECTOR_BYTES)] != list(range(start, start + VECTOR_BYTES)):
            raise ValueError("constructor vec3 copy is noncontiguous")
        offsets.append(start)
    if len(set(offsets)) != 3 or any(
        a < b + VECTOR_BYTES and b < a + VECTOR_BYTES for i, a in enumerate(offsets) for b in offsets[i + 1 :]
    ):
        raise ValueError("constructor vectors overlap")
    return {"origin": offsets[0], "angles": offsets[1]}


def _dominates(instructions, definition, use):
    pending, seen = [0], set()
    while pending:
        index = pending.pop()
        if index == definition or index in seen or index >= len(instructions):
            continue
        if index == use:
            return False
        seen.add(index)
        item = instructions[index]
        successors = item.get("successors")
        if successors is None:
            if item["mnemonic"].startswith("j"):
                return False
            successors = [] if item["mnemonic"].startswith("ret") else [index + 1]
        pending.extend(successors)
    return True


def _spilled_source(instructions, use, origin, mode):
    # GCC keeps Source* = list_node + link_header in a stack local, while
    # loading mode directly through the retained list-node register. Recover
    # that relation only from dominating definitions with no intervening writes.
    if not origin or origin[0] != "load" or origin[1][1] != "stack":
        return None
    if not mode or mode[0] != "load":
        return None
    root = mode[1][1]
    if not isinstance(root, tuple) or root[0] != "entry":
        return None
    base = root[1]
    slot = origin[1][2]
    stores = [
        i
        for i, item in enumerate(instructions[:use])
        if item["mnemonic"] == "mov"
        and item["operands"][0] == {"kind": "mem", "size": WORD, "base": "esp", "disp": slot}
    ]
    if len(stores) != 1:
        return None
    store = stores[0]
    source = instructions[store]["operands"][1]
    if source.get("kind") != "reg" or not _dominates(instructions, store, use):
        return None
    register = source["reg"]
    for definition in range(store - 1, max(-1, store - 80), -1):
        item = instructions[definition]
        if register not in item.get("writes", ()):
            continue
        ops = item["operands"]
        if item["mnemonic"] != "lea" or ops[1].get("base") != base or not _dominates(instructions, definition, store):
            return None
        for intervening in instructions[definition + 1 : use]:
            if (
                base in intervening.get("writes", ())
                or "esp" in intervening.get("writes", ())
                or intervening.get("stack_delta", 0)
            ):
                return None
            for operand in intervening.get("memory_writes", ()):
                if (
                    operand.get("base") == "esp"
                    and operand.get("disp", 0) < slot + WORD
                    and slot < operand.get("disp", 0) + operand.get("size", 0)
                    and intervening is not instructions[store]
                ):
                    return None
        return ("ptr", root, ops[1].get("disp", 0))
    return None


def source_mode_offset(instructions, platform, clip_ea):
    candidates = set()
    for index, insn in enumerate(instructions):
        if insn["mnemonic"] != "call" or insn["operands"] != [{"kind": "func", "size": WORD, "value": clip_ea}]:
            continue
        start = index
        while start and index - start < 60 and not instructions[start - 1]["mnemonic"].startswith(("j", "call", "ret")):
            start -= 1
        trace = Trace(platform)
        for item in instructions[start:index]:
            trace.step(item)
        args = trace.arguments(10)
        mode, origin = (args[0], args[3]) if platform == "windows" else (args[1], args[4])
        if platform == "linux":
            origin = _spilled_source(instructions, index, origin, mode) or origin
        origin = pointer(origin)
        if mode and mode[0] == "load" and mode[2] == WORD and origin and mode[1][1] == origin[1]:
            offset = mode[1][2] - origin[2]
            if offset >= 0 and offset % WORD == 0:
                candidates.add(offset)
    if len(candidates) != 1:
        raise ValueError("portal source mode argument evidence is missing or ambiguous")
    return next(iter(candidates))


def getter_return(instructions, platform):
    """Summarize a branch-free accessor using its actual this argument."""
    if len(instructions) > 12:
        return None
    trace = Trace(platform, constructor=True)
    for item in instructions:
        if item["mnemonic"].startswith("ret"):
            return trace.registers.get("eax")
        if item["mnemonic"] not in {"mov", "lea", "add", "sub", "push", "pop"}:
            return None
        trace.step(item)
    return None


def _substitute_this(value, this):
    if not isinstance(value, tuple):
        return value
    if len(value) == 3 and value[:2] == ("ptr", "this"):
        return pointer(this, value[2])
    return tuple(_substitute_this(part, this) for part in value)


def client_transform_offsets(instructions, platform, clip_ea, getters):
    """Prove CalculateClipPlane's mode and entity vectors share one ClientPortal."""
    candidates = set()
    for index, item in enumerate(instructions):
        if item["mnemonic"] != "call" or item["operands"] != [{"kind": "func", "size": WORD, "value": clip_ea}]:
            continue
        start = index
        while (
            start and index - start < TRACE_LIMIT and not instructions[start - 1]["mnemonic"].startswith(("j", "ret"))
        ):
            start -= 1
        trace = Trace(platform)
        for instruction in instructions[start:index]:
            summary = None
            if instruction["mnemonic"] == "call" and instruction["operands"]:
                summary = getters.get(instruction["operands"][0].get("value"))
            this = trace.arguments(1)[0] if platform == "linux" else trace.registers.get("ecx")
            trace.step(instruction)
            if summary is not None and this is not None:
                trace.registers["eax"] = _substitute_this(summary, this)
        args = trace.arguments(10)
        if platform == "linux":
            args = args[1:]
        mode, origin, angles, owner, source_angles = (
            args[0],
            pointer(args[3]),
            pointer(args[4]),
            pointer(args[5]),
            pointer(args[6]),
        )
        if not all((mode, origin, angles, owner, source_angles)) or mode[0] != "load" or mode[2] != WORD:
            continue
        if source_angles != pointer(owner, VECTOR_BYTES) or mode[1][1] != owner[1]:
            continue
        entity_load = origin[1]
        if not isinstance(entity_load, tuple) or entity_load[0] != "load" or entity_load[2] != WORD:
            continue
        if angles[1] != entity_load or entity_load[1][1] != owner[1] or angles[2] != origin[2] + VECTOR_BYTES:
            continue
        values = (mode[1][2] - owner[2], entity_load[1][2] - owner[2], origin[2], angles[2])
        if all(value >= 0 and value % WORD == 0 for value in values):
            candidates.add(values)
    if len(candidates) != 1:
        raise ValueError("ClientPortal entity/transform call arguments are missing or ambiguous")
    return dict(zip(("mode", "entity", "origin", "angles"), next(iter(candidates))))


def _entry_register(instructions, use, register, expected):
    predecessors = {i: [] for i in range(len(instructions))}
    for i, item in enumerate(instructions):
        successors = item.get("successors")
        if successors is None:
            if item["mnemonic"].startswith("j"):
                return False
            successors = [] if item["mnemonic"].startswith("ret") else [i + 1]
        for target in successors:
            if target in predecessors:
                predecessors[target].append(i)
    pending, seen, roots = [(use, register)], set(), set()
    while pending:
        index, reg = pending.pop()
        state = (index, reg)
        if state in seen:
            continue
        seen.add(state)
        if len(seen) > 2048:
            return False
        if index == 0:
            roots.add(reg)
        for previous in predecessors[index]:
            item = instructions[previous]
            ops = item["operands"]
            if item["mnemonic"] not in {
                "mov",
                "lea",
                "push",
                "pop",
                "add",
                "sub",
                "call",
                "cmp",
                "test",
                "nop",
            } and not item["mnemonic"].startswith(("j", "ret")):
                return False
            writes = set(item.get("writes", ()))
            if item["mnemonic"] == "call":
                writes.update(item.get("call_writes", ("eax", "ecx", "edx")))
            if ops and ops[0].get("kind") == "reg" and item["mnemonic"] in {"mov", "lea", "add", "sub"}:
                writes.add(ops[0]["reg"])
            if reg in writes:
                if (
                    item["mnemonic"] == "mov"
                    and len(ops) == 2
                    and ops[0] == {"kind": "reg", "size": WORD, "reg": reg}
                    and ops[1].get("kind") == "reg"
                    and ops[1].get("size") == WORD
                ):
                    pending.append((previous, ops[1]["reg"]))
                elif (
                    item["mnemonic"] == "mov"
                    and len(ops) == 2
                    and ops[1].get("kind") == "mem"
                    and ops[1].get("base") == "esp"
                    and ops[1].get("size") == WORD
                    and item.get("stack_offset") is not None
                    and ops[1].get("disp", 0) + item["stack_offset"] == WORD
                ):
                    roots.add("stack_this")
                else:
                    return False
            else:
                pending.append((previous, reg))
    return roots == {expected} or roots == {"stack_this"}


def linux_texture_offsets(instructions):
    """Follow the successful straight-line GL allocation/bind/upload block."""
    candidates = set()
    for start, insn in enumerate(instructions):
        if insn["mnemonic"] != "call" or not insn["operands"] or insn["operands"][0].get("name") != "glGenTextures":
            continue
        block = start
        while block and start - block < 16 and not instructions[block - 1]["mnemonic"].startswith(("j", "call", "ret")):
            block -= 1
        trace = Trace("linux", constructor=True)
        trace.registers["esp"] = ("ptr", "stack", instructions[block].get("stack_offset", 0))
        for item in instructions[block:start]:
            trace.step(item)
        count, texture = trace.arguments(2)
        if count != ("constant", 1) or not texture or texture[0] != "ptr":
            continue
        root = texture[1]
        if root != "this" and (
            not isinstance(root, tuple)
            or root[0] != "entry"
            or not _entry_register(instructions, block, root[1], "eax")
        ):
            continue
        bound = False
        for item in instructions[start : start + 60]:
            if item["mnemonic"].startswith(("j", "ret")):
                break
            if item["mnemonic"] == "call":
                api = item["operands"][0].get("name")
                args = trace.arguments(9)
                if api == "glBindTexture":
                    bound = args[:2] == [("constant", GL_TEXTURE_2D), ("load", texture, WORD)]
                elif api == "glTexImage2D":
                    width, height = args[3:5]
                    if (
                        bound
                        and args[0] == ("constant", GL_TEXTURE_2D)
                        and all(v and v[0] == "load" and v[2] == WORD for v in (width, height))
                    ):
                        if width[1] == pointer(texture, WORD) and height[1] == pointer(texture, 2 * WORD):
                            candidates.add((texture[2], width[1][2], height[1][2]))
                    break
                elif api not in {"glGenTextures", "glEnable"}:
                    break
            trace.step(item)
    if len(candidates) != 1:
        raise ValueError("Linux portal GL argument evidence is missing or ambiguous")
    texture, width, height = next(iter(candidates))
    return {"texture_id": texture, "texture_width": width, "texture_height": height}
