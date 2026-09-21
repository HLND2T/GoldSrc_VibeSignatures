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


def decode_function_flow(function, instruction_eas, *, noreturn_calls=()):
    """Copy block edges; only caller-verified non-returning calls terminate flow.

    IDA can misidentify ordinary callees as library exit functions. Preserve
    their possible return edge instead of trusting inferred FUNC_NORET flags.
    """
    import ida_bytes
    import ida_gdl
    import idc

    addresses = list(instruction_eas)
    successors = {ea: None for ea in addresses}
    for block in ida_gdl.FlowChart(function):
        items = [ea for ea in addresses if block.start_ea <= ea < block.end_ea]
        for index, ea in enumerate(items):
            successors[ea] = [items[index + 1]] if index + 1 < len(items) else [int(s.start_ea) for s in block.succs()]
    for ea in addresses:
        mnemonic = (idc.print_insn_mnem(ea) or "").lower()
        if mnemonic == "call":
            next_ea = ea + int(ida_bytes.get_item_size(ea))
            successors[ea] = [] if ea in noreturn_calls else [next_ea]
        elif successors[ea] == [] and mnemonic not in ("ret", "retn", "retf", "ud2", "hlt"):
            # An unresolved jump or truncated block is not a proven exit.
            successors[ea] = None
    return successors


def compiler_noreturn_imports():
    """Use import-table identity, never IDA's inferred local function names."""
    import ida_nalt

    targets = set()

    def collect(ea, name, ordinal):
        if name and name.split("@", 1)[0] == "__stack_chk_fail":
            targets.add(int(ea))
        return True

    for index in range(ida_nalt.get_import_module_qty()):
        ida_nalt.enum_import_names(index, collect)
    return targets


def _control_flow(instructions):
    """Index explicit decoded edges; unknown destinations remain unknown edges."""
    addresses = [_instruction_ea(instruction) for instruction in instructions]
    by_ea = {ea: index for index, ea in enumerate(addresses) if ea is not None}
    addressed = len(by_ea) == len(instructions)
    graph = []
    for index, instruction in enumerate(instructions):
        mnemonic = instruction["mnem"]
        following = index + 1 if index + 1 < len(instructions) else None
        if "successors" in instruction:
            edges = instruction["successors"]
            graph.append([by_ea.get(ea) for ea in edges] if addressed and edges is not None else [None])
        elif mnemonic.startswith("j") or mnemonic.startswith("loop"):
            target = by_ea.get(_jump_target(instruction)) if addressed else None
            graph.append([target] if mnemonic.startswith("jmp") else [target, following])
        elif mnemonic in ("ret", "retn", "retf", "ud2", "hlt"):
            graph.append([])
        else:
            graph.append([following])
    return graph


def _may_reach(graph, start, goal, blocked=None):
    """Unknown edges may reach any node; never infer termination from address order."""
    pending = [start]
    visited = set()
    while pending:
        index = pending.pop()
        if index is None:
            return True
        if index == blocked or index in visited:
            continue
        if index == goal:
            return True
        visited.add(index)
        pending.extend(graph[index])
    return False


def recover_call_arguments(instructions, call_index, arity):
    graph = _control_flow(instructions)

    def dominates(def_index, use_index):
        return _may_reach(graph, 0, use_index) and not _may_reach(graph, 0, use_index, blocked=def_index)

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
            if mnemonic.startswith("loop") or mnemonic in ("ret", "retn") or mnemonic in UNCONDITIONAL_JUMPS:
                return None
            if mnemonic.startswith("j"):
                if not (_is_conditional_jump(mnemonic) and kind == "reg" and value not in CALLER_SAVED):
                    return None
                # The lexical fall-through path is examined below. Every other
                # edge must be proven unable to return to this use.
                if any(_may_reach(graph, edge, index) for edge in graph[previous] if edge != previous + 1):
                    return None
                continue
            if mnemonic == "call":
                if kind == "stack" or value in CALLER_SAVED:
                    return None
                continue
            if mnemonic == "push" and operand == ("stack", instruction["sp"] - WORD):
                if not dominates(previous, index):
                    return None
                return read_before(previous, operands[0])
            if operands and operands[0] == operand:
                if not dominates(previous, index):
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
