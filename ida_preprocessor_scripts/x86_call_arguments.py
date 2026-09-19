"""Recover concrete x86 call arguments from decoded stack-frame writes.

Stack operands and ``sp`` are relative to the function's incoming ESP.
Unknown writes, branches, and caller-clobbered registers fail closed.
"""

WORD = 4
CALLER_SAVED = {"eax", "ecx", "edx"}


def recover_call_arguments(instructions, call_index, arity):
    def read_before(index, operand):
        kind, value = operand
        if kind == "imm":
            return value
        if kind not in ("reg", "stack"):
            return None
        for previous in range(index - 1, -1, -1):
            instruction = instructions[previous]
            mnemonic = instruction["mnem"]
            operands = instruction["ops"]
            if mnemonic.startswith("j") or mnemonic.startswith("loop") or mnemonic in ("ret", "retn"):
                return None
            if mnemonic == "call":
                if kind == "stack" or value in CALLER_SAVED:
                    return None
                continue
            if mnemonic == "push" and operand == ("stack", instruction["sp"] - WORD):
                return read_before(previous, operands[0])
            if operands and operands[0] == operand:
                if mnemonic == "mov" and len(operands) == 2:
                    return read_before(previous, operands[1])
                if mnemonic == "xor" and len(operands) == 2 and operands[1] == operand:
                    return 0
                if mnemonic not in ("cmp", "test", "push"):
                    return None
        return None

    stack_pointer = instructions[call_index]["sp"]
    return [read_before(call_index, ("stack", stack_pointer + WORD * i)) for i in range(arity)]
