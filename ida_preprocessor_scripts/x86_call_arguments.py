"""Recover concrete x86 call arguments from decoded stack-frame writes.

Stack operands and ``sp`` are relative to the function's incoming ESP.
Unknown writes, unconditional branches, and caller-clobbered registers fail
closed. A definition is accepted only when it dominates the use: a ``jcc``
may be crossed when following a callee-saved register if its taken target
does not reach the use, and no earlier ``jcc`` can skip the definition
while still reaching the use.
"""

WORD = 4
CALLER_SAVED = {"eax", "ecx", "edx"}
UNCONDITIONAL_JUMPS = {"jmp", "jmpn", "jmpe"}


def _is_conditional_jump(mnemonic):
    return mnemonic.startswith("j") and mnemonic not in UNCONDITIONAL_JUMPS and not mnemonic.startswith("jmp")


def _instruction_ea(instruction):
    try:
        return int(instruction["ea"])
    except (KeyError, TypeError, ValueError):
        return None


def _jump_target(instruction):
    for operand in instruction.get("ops") or ():
        if operand and operand[0] == "imm":
            try:
                return int(operand[1])
            except (TypeError, ValueError):
                return None
    return None


def _jcc_skips_definition(instructions, def_index, use_index):
    def_ea = _instruction_ea(instructions[def_index])
    use_ea = _instruction_ea(instructions[use_index])
    for index in range(def_index):
        instruction = instructions[index]
        if not _is_conditional_jump(instruction["mnem"]):
            continue
        if def_ea is None or use_ea is None:
            return True
        target = _jump_target(instruction)
        if target is None or def_ea < target <= use_ea:
            return True
    return False


def recover_call_arguments(instructions, call_index, arity):
    def read_before(index, operand):
        kind, value = operand
        if kind == "imm":
            return value
        if kind not in ("reg", "stack"):
            return None
        use_ea = _instruction_ea(instructions[index])
        for previous in range(index - 1, -1, -1):
            instruction = instructions[previous]
            mnemonic = instruction["mnem"]
            operands = instruction["ops"]
            if mnemonic.startswith("loop") or mnemonic in ("ret", "retn") or mnemonic in UNCONDITIONAL_JUMPS:
                return None
            if mnemonic.startswith("j"):
                if not (_is_conditional_jump(mnemonic) and kind == "reg" and value not in CALLER_SAVED):
                    return None
                target = _jump_target(instruction)
                insn_ea = _instruction_ea(instruction)
                if target is None or use_ea is None or insn_ea is None or target <= insn_ea or target <= use_ea:
                    return None
                continue
            if mnemonic == "call":
                if kind == "stack" or value in CALLER_SAVED:
                    return None
                continue
            if mnemonic == "push" and operand == ("stack", instruction["sp"] - WORD):
                if _jcc_skips_definition(instructions, previous, index):
                    return None
                return read_before(previous, operands[0])
            if operands and operands[0] == operand:
                if _jcc_skips_definition(instructions, previous, index):
                    return None
                if mnemonic == "mov" and len(operands) == 2:
                    return read_before(previous, operands[1])
                if mnemonic == "xor" and len(operands) == 2 and operands[1] == operand:
                    return 0
                if mnemonic not in ("cmp", "test", "push"):
                    return None
        return None

    stack_pointer = instructions[call_index]["sp"]
    return [read_before(call_index, ("stack", stack_pointer + WORD * i)) for i in range(arity)]
