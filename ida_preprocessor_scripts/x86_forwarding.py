"""Small fail-closed dataflow model for decoded straight-line x86 call sites.

Operands are (kind, value): reg, imm, stack (raw ESP displacement), symbol
(imported function pointer), or unknown. This is not a general x86 emulator.
"""

WORD = 4
ARGUMENT_COUNT = 8
GL_ARITY = {
    "glDisable": 1,
    "glEnable": 1,
    "glTexEnvf": 3,
    "glBlendFunc": 2,
    "glColor4f": 4,
    "glBegin": 1,
    "glVertex2f": 2,
    "glEnd": 0,
    "glColor3f": 3,
}
CALLEE_SAVED = ("ebx", "esi", "edi", "ebp")


def trace_calls(instructions, platform, forwarding=False):
    """Return [(resolved target, arguments)] or reject unsupported/unsafe flow."""
    if platform not in ("windows", "linux"):
        raise ValueError("unsupported ABI")
    registers = {r: ("saved", r) for r in CALLEE_SAVED}
    stack = {WORD * (i + 1): ("arg", i) for i in range(ARGUMENT_COUNT)}
    esp = 0
    calls = []
    returned = False

    def read(operand):
        kind, value = operand
        if kind == "reg":
            return registers.get(value)
        if kind == "stack":
            return stack.get(esp + value)
        if kind == "imm":
            return value
        if kind == "symbol":
            return ("gl", value)
        return None

    def write(operand, value):
        kind, where = operand
        if kind == "reg" and where != "esp":
            registers[where] = value
        elif kind == "stack":
            if forwarding and esp + where >= 0:
                raise ValueError("wrapper overwrites caller frame")
            stack[esp + where] = value
        else:
            raise ValueError("unsupported write")

    for instruction in instructions:
        if returned:
            raise ValueError("instructions after return")
        mnem = instruction["mnem"]
        operands = instruction["ops"]
        dest = operands[0] if operands else ("unknown", None)
        source = operands[1] if len(operands) > 1 else ("unknown", None)
        if mnem == "push":
            value = read(dest)
            esp -= WORD
            stack[esp] = value
        elif mnem == "pop":
            write(dest, stack.get(esp))
            esp += WORD
        elif mnem in ("add", "sub") and dest == ("reg", "esp") and source[0] == "imm":
            esp += source[1] if mnem == "add" else -source[1]
        elif mnem == "mov":
            write(dest, read(source))
        elif mnem == "call":
            target = instruction.get("target") or read(dest)
            if not target:
                raise ValueError("unresolved call")
            if target[0] == "pic":
                # Verified get-PC thunk writes only its destination register.
                registers[target[1]] = None
                continue
            if forwarding:
                if target[0] != "body" or calls:
                    raise ValueError("wrapper has multiple/non-body calls")
                args = [stack.get(esp + i * WORD) for i in range(ARGUMENT_COUNT)]
                if args != [("arg", i) for i in range(ARGUMENT_COUNT)]:
                    raise ValueError("wrapper changes arguments")
                arity = ARGUMENT_COUNT
            else:
                if target[0] != "gl" or target[1] not in GL_ARITY:
                    raise ValueError("unexpected draw callee")
                arity = GL_ARITY[target[1]]
                args = [stack.get(esp + i * WORD) for i in range(arity)]
            calls.append((target, args))
            for reg in ("eax", "ecx", "edx"):
                registers[reg] = None
            if platform == "windows" and target[0] == "gl":
                esp += arity * WORD  # OpenGL uses stdcall on Win32.
        elif mnem in ("ret", "retn"):
            if operands or esp != 0:
                raise ValueError("unbalanced stack or non-cdecl return")
            if any(registers.get(r) != ("saved", r) for r in CALLEE_SAVED):
                raise ValueError("callee-saved register not restored")
            returned = True
        elif mnem == "add" and dest == ("reg", "ebx") and source[0] == "imm":
            registers["ebx"] = None  # PIC base setup, not an argument definition.
        elif not forwarding and mnem in ("add", "sub") and dest[0] == "reg" and dest[1] != "esp":
            write(dest, None)
        elif not forwarding and mnem in ("fst", "fstp"):
            if dest[0] == "stack":
                write(dest, None)
            elif dest[0] != "unknown":
                raise ValueError("unexpected floating-point store")
        elif not forwarding and mnem in (
            "fld",
            "fld1",
            "fild",
            "fmul",
            "fimul",
            "fdiv",
            "fdivrp",
            "fxch",
            "fadd",
            "faddp",
        ):
            pass  # Float calculations cannot establish integer GL enum arguments.
        else:
            raise ValueError("unsupported instruction: " + mnem)
    if not returned or not calls:
        raise ValueError("missing return or call")
    return calls
