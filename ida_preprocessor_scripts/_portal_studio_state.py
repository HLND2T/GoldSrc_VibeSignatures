"""Recover the one-shot portal studio byte from reset and read/clear behavior."""

import copy

from ida_preprocessor_scripts._portal_layout import Trace


def reset_bytes(instructions, platform):
    """Only inspect this-owned byte clears before native cleanup starts."""
    pending = [(0, Trace(platform, constructor=True))]
    seen = set()
    result = set()
    while pending:
        index, state = pending.pop()
        if not 0 <= index < len(instructions):
            continue
        key = (index, repr(state.registers), repr(state.memory))
        if key in seen:
            continue
        seen.add(key)
        if len(seen) > 256:
            raise ValueError("portal reset prefix exceeds its bound")
        item = instructions[index]
        if item.get("stack_offset") is not None:
            state.registers["esp"] = ("ptr", "stack", item["stack_offset"])
        mnemonic, ops = item["mnemonic"], item["operands"]
        if mnemonic.startswith("ret") or (mnemonic == "call" and "call_writes" not in item):
            continue
        if mnemonic == "mov" and len(ops) == 2:
            address = state.address(ops[0])
            if (
                address
                and address[:2] == ("ptr", "this")
                and 0 < address[2] <= 0xFFFFFFFF
                and ops[0].get("size") == 1
                and state.value(ops[1]) == ("constant", 0)
            ):
                result.add((address[2], item["ea"]))
        if mnemonic == "call":
            # GCC's get_pc_thunk changes only its declared destination register.
            for register in item["call_writes"]:
                state.registers.pop(register, None)
        elif mnemonic in {"xorps", "pxor"} and all(
            op.get("kind") == "reg" and op.get("reg", "").startswith("xmm") for op in ops
        ):
            for register in item.get("writes", ()):
                state.registers.pop(register, None)
        elif not mnemonic.startswith("j"):
            state.step(item)
        successors = item.get("successors", [index + 1])
        if any(target <= index for target in successors):
            raise ValueError("loop in portal reset prefix")
        pending.extend((target, copy.deepcopy(state)) for target in successors)
    return result


def calls(instructions, targets):
    return any(
        item["mnemonic"] == "call"
        and len(item["operands"]) == 1
        and item["operands"][0].get("kind") == "func"
        and item["operands"][0].get("value") in targets
        for item in instructions
    )


def consume_bytes(instructions, resetters):
    """A reset caller returns the old byte and clears that exact memory operand."""
    if not calls(instructions, resetters):
        return set()
    result = set()
    for index, load in enumerate(instructions[:-1]):
        ops = load["operands"]
        if load["mnemonic"] not in {"mov", "movzx"} or len(ops) != 2:
            continue
        dst, src = ops
        if (
            dst.get("kind") != "reg"
            or (dst.get("reg"), dst.get("size")) != (("al", 1) if load["mnemonic"] == "mov" else ("eax", 4))
            or src.get("kind") != "mem"
            or src.get("size") != 1
            or src.get("base") in {"esp", "ebp"}
            or src.get("disp", 0) <= 0
        ):
            continue
        clear = instructions[index + 1]
        if (
            clear["mnemonic"] != "mov"
            or len(clear["operands"]) != 2
            or clear["operands"][0] != src
            or clear["operands"][1].get("kind") != "imm"
            or clear["operands"][1].get("value") != 0
            or load.get("successors", [index + 1]) != [index + 1]
            or clear.get("successors", [index + 2]) != [index + 2]
        ):
            continue
        # The read must actually be the return value, not an unused temporary.
        cursor = index + 2
        while cursor < len(instructions):
            item = instructions[cursor]
            if item["mnemonic"] in {"ret", "retn"}:
                result.add((src["disp"], load["ea"]))
                break
            if (
                item["mnemonic"].startswith(("j", "call"))
                or set(item.get("writes", ())) & {"eax", "ax", "al", "ah"}
                or item.get("successors", [cursor + 1]) != [cursor + 1]
            ):
                break
            cursor += 1
    return result


def recover_studio_member(reset, instructions, callers, platform):
    if platform not in {"windows", "linux"}:
        raise ValueError("portal studio state requires Windows/Linux x86")
    clears = reset_bytes(instructions, platform)
    resetters = {reset}
    # Windows inlines lazy construction; Linux uses a shared singleton helper.
    for _ in range(2):
        resetters |= {owner for owner, body in callers.items() if calls(body, resetters)}
    consumers = {
        (offset, owner, ea) for owner, body in callers.items() for offset, ea in consume_bytes(body, resetters)
    }
    matches = {
        (offset, clear, owner, read) for offset, clear in clears for other, owner, read in consumers if offset == other
    }
    if len(matches) != 1:
        raise ValueError("portal studio reset/read-clear evidence is missing or ambiguous")
    offset, instruction, accessor, read = matches.pop()
    return {"offset": offset, "size": 1, "instruction": instruction, "accessor": accessor, "read": read}
