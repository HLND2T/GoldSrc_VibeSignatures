"""Conservative x86 affine dataflow evidence for a masked frame-ring index.

This is an offline verifier, not a runtime expression interpreter. Unknown arithmetic,
control-flow joins, partial register writes and conflicting paths fail closed.
"""

import re

REGISTERS = frozenset(("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"))
REGISTER_TERM = re.compile(r"\b(eax|ebx|ecx|edx|esi|edi|ebp|esp)\b(?:\s*\*\s*([1248]))?", re.I)
MIN_FRAME_STRIDE = 0x4000  # Excludes entity-state indexing; semantic mapping is still required.
STUDIO_PLAYER_CALL = re.compile(r"call\s+.*\[[^\]]+\+(?:8h?|0x8)\]$", re.I)
ADDRESS_LINE = re.compile(r"^\s*(?:[^:\s]+:)?(?:0x)?([0-9a-fA-F]{4,16}):?\s+(.+)$")
MAX_CHAIN_INSTRUCTIONS = 96


def build_stack_operand_export_py_eval(func_va):
    """Read encoded ESP displacements without trusting IDA's named stack variables."""
    return f"""
import ida_ua, idautils, idc, json, re
offsets = {{}}
for ea in idautils.FuncItems({int(func_va)}):
    insn = ida_ua.insn_t()
    if not ida_ua.decode_insn(insn, ea):
        continue
    op = insn.ops[0]
    text = idc.print_operand(ea, 0).lower()
    regs = re.findall(r"\\b(?:eax|ebx|ecx|edx|esi|edi|ebp|esp)\\b", text)
    if (op.type in (ida_ua.o_displ, ida_ua.o_phrase) and regs == ['esp']
            and ida_ua.get_dtype_size(op.dtype) == 4):
        offsets[str(ea)] = int(op.addr) if op.type == ida_ua.o_displ else 0
json.dumps({{'stack_displacements': offsets}})
"""


def _number(value):
    value = value.strip().lower()
    try:
        return int(value[:-1], 16) if value.endswith("h") else int(value, 0)
    except ValueError:
        return None


def _parent_register(value):
    for register in REGISTERS:
        aliases = {register, register[1:]}
        if register in {"eax", "ebx", "ecx", "edx"}:
            aliases.update({register[1] + "l", register[1] + "h"})
        if value in aliases:
            return register
    return None


def _coefficient(operand, registers, *, address=False):
    operand = operand.strip().lower()
    if operand in REGISTERS:
        return registers[operand]
    terms = list(REGISTER_TERM.finditer(operand))
    if not terms:
        return 0  # Constants and independent globals do not depend on the masked index.
    if not address:
        return None if any(registers[m[1]] != 0 for m in terms) else 0
    result = 0
    for match in terms:
        coefficient = registers[match[1]]
        if coefficient is None:
            return None
        prefix = operand[: match.start()].rstrip()
        sign = -1 if prefix.endswith("-") else 1
        result += sign * coefficient * int(match[2] or 1)
    return result


def recover_masked_index_stride(disasm, *, stack_displacements=None):
    from ida_llm_decompile import _strip_disasm_comments

    instructions = []
    joins = set()
    for raw in _strip_disasm_comments(disasm).splitlines():
        match = ADDRESS_LINE.match(raw)
        address, line = (int(match[1], 16), match[2]) if match else (None, raw.strip())
        parts = line.lower().split(None, 1)
        if not parts:
            continue
        mnemonic = parts[0]
        operands = [item.strip() for item in parts[1].split(",")] if len(parts) > 1 else []
        if mnemonic.startswith("j") and operands:
            target = re.search(r"(?:loc_|locret_|0x)([0-9a-f]+)$", operands[0])
            if target:
                joins.add(int(target[1], 16))
        instructions.append((address, line, mnemonic, operands))
    evidence = []
    player_calls = set()
    callees = set()
    for index, (address, line, mnemonic, operands) in enumerate(instructions):
        if address in joins or mnemonic.startswith(("j", "ret", "loop")):
            callees.clear()
        if mnemonic == "call":
            if STUDIO_PLAYER_CALL.fullmatch(line.strip()) or operands and operands[0] in callees:
                player_calls.add(index)
            callees.clear()
        elif operands and (parent := _parent_register(operands[0])):
            forwarded = (
                mnemonic == "mov"
                and len(operands) == 2
                and operands[0] in REGISTERS
                and (operands[1] in callees or STUDIO_PLAYER_CALL.fullmatch("call " + operands[1]))
            )
            if mnemonic not in {"cmp", "test"}:
                callees.discard(parent)
                if forwarded:
                    callees.add(parent)
    verified_calls = set()
    for index, (seed_address, seed, mnemonic, operands) in enumerate(instructions):
        if mnemonic != "and" or len(operands) != 2 or operands[0] not in REGISTERS:
            continue
        registers = dict.fromkeys(REGISTERS, 0)
        registers[operands[0]] = 1
        pushed, stores, chain = [], {}, [f"{seed_address:#x}: {seed}" if seed_address is not None else seed]
        for call_index, (address, line, mnemonic, operands) in enumerate(
            instructions[index + 1 : index + 1 + MAX_CHAIN_INSTRUCTIONS], start=index + 1
        ):
            if address in joins or mnemonic.startswith(("j", "ret", "loop")) or mnemonic == "and":
                break
            chain.append(f"{address:#x}: {line}" if address is not None else line)
            if mnemonic == "call":
                if call_index in player_calls:
                    arguments = [pushed[-2]] if len(pushed) >= 2 and pushed[-1] == 0 else []
                    if 4 in stores:
                        arguments.append(stores[4])
                    values = {
                        value for value in arguments if value is not None and MIN_FRAME_STRIDE < value <= 0xFFFFFFFF
                    }
                    if len(values) > 1:
                        raise ValueError("ambiguous frame argument coefficients")
                    if values:
                        evidence.append({"value": values.pop(), "instructions": chain})
                        verified_calls.add(call_index)
                break
            if mnemonic not in {
                "mov",
                "lea",
                "add",
                "sub",
                "inc",
                "dec",
                "imul",
                "shl",
                "sal",
                "xor",
                "push",
                "cmp",
                "test",
                "nop",
            }:
                break
            if not operands:
                continue
            destination = operands[0]
            if mnemonic == "push":
                if stores:
                    break
                pushed.append(_coefficient(destination, registers))
                continue
            if mnemonic == "mov" and len(operands) == 2 and "[" in destination and re.search(r"\besp\b", destination):
                if stack_displacements is not None:
                    offset = stack_displacements.get(str(address))
                else:
                    numeric = re.fullmatch(r"(?:dword ptr )?\[esp(?:\+(0x[0-9a-f]+|[0-9a-f]+h|\d+))?\]", destination)
                    offset = _number(numeric[1]) if numeric and numeric[1] else 0 if numeric else None
                if offset is None:
                    break
                stores[offset] = _coefficient(operands[1], registers)
                continue
            parent = _parent_register(destination)
            if not parent or mnemonic in {"test", "cmp", "nop"}:
                continue
            if mnemonic not in {"mov", "lea", "add", "sub", "inc", "dec", "imul", "shl", "sal", "xor"}:
                break  # Unknown instructions may also clobber other or implicit registers.
            if parent == "esp" and stores:
                break  # Previously stored arguments no longer have a proven call-site stack slot.
            value = None
            if destination in REGISTERS:
                if mnemonic in {"inc", "dec"}:
                    value = registers[parent]  # +/- an independent constant preserves the coefficient.
                elif mnemonic == "mov" and len(operands) == 2:
                    value = _coefficient(operands[1], registers)
                elif mnemonic == "lea" and len(operands) == 2:
                    value = _coefficient(operands[1], registers, address=True)
                elif mnemonic in {"add", "sub"} and len(operands) == 2:
                    other = _coefficient(operands[1], registers)
                    if registers[parent] is not None and other is not None:
                        value = registers[parent] + (other if mnemonic == "add" else -other)
                elif mnemonic == "imul" and len(operands) in {2, 3}:
                    factor = _number(operands[-1])
                    source = _coefficient(operands[-2], registers)
                    if factor is not None and source is not None:
                        value = source * factor
                elif mnemonic in {"shl", "sal"} and len(operands) == 2:
                    shift = _number(operands[1])
                    if shift is not None and 0 <= shift <= 31 and registers[parent] is not None:
                        value = registers[parent] << shift
                elif mnemonic == "xor" and len(operands) == 2 and operands[1] == parent:
                    value = 0
            registers[parent] = value
    values = {item["value"] for item in evidence}
    if len(values) != 1 or verified_calls != player_calls:
        raise ValueError("no unique masked frame-ring stride reaches StudioDrawPlayer")
    return values.pop(), evidence
