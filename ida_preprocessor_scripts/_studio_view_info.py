"""Prove four vec3 copies by their destination arguments, not instruction order.

The bounded interpreter accepts only the straight-line x86 forms observed in
GetViewInfo. Unknown instructions, indexed addressing, extra output stores and
incomplete copies fail closed. Values retain their originating disp32 operand
through register transfers, x87 loads and GOT/GOTOFF address materialization.
"""

import inspect

from ida_preprocessor_scripts._engine_private_globals_common import run_walk


def recover_vectors(code, writable_ranges, got_slots):
    """Return the four source addresses and their operand provenance, or raise."""
    word = 4
    components = 3
    arguments = 4
    registers = {"esp": ("stack", 0, None)}
    stack = {}
    floating = []
    stores = {}
    returned = False

    def writable(address):
        return any(start <= address and address + word <= end for start, end in writable_ranges)

    def effective(operand):
        if operand["kind"] != "mem" or operand["width"] != word:
            raise ValueError("expected scalar memory operand")
        base = operand.get("base")
        offset = operand["offset"]
        if base is None:
            return ("ptr", offset, None)
        value = registers.get(base)
        if value is None or value[0] not in ("ptr", "stack", "arg"):
            raise ValueError("unknown memory base")
        if value[0] == "arg":
            return ("arg", value[1], value[2] + offset)
        return (value[0], (value[1] + offset) if value[0] == "stack" else (value[1] + offset) & 0xFFFFFFFF, value[2])

    def read(operand, site):
        kind = operand["kind"]
        if kind == "reg":
            if operand["width"] != word:
                raise ValueError("partial register access")
            return registers.get(operand["name"])
        if kind == "imm":
            return ("constant", operand["value"], None)
        address = effective(operand)
        if address[0] == "stack":
            offset = address[1]
            if offset in range(word, word * (arguments + 1), word):
                return ("arg", offset // word - 1, 0)
            return stack.get(offset)
        if address[0] != "ptr":
            raise ValueError("read from output argument")
        pointer = address[1]
        origin = site if operand.get("disp32") else address[2]
        if pointer in got_slots:
            target = got_slots[pointer]
            if not writable(target) or origin is None:
                raise ValueError("invalid GOT pointee")
            return ("ptr", target, origin)
        if not writable(pointer) or origin is None:
            raise ValueError("global read lacks writable storage or provenance")
        return ("value", pointer, origin)

    def write(operand, value):
        if operand["kind"] == "reg":
            if operand["width"] != word:
                raise ValueError("partial register write")
            registers[operand["name"]] = value
            return
        address = effective(operand)
        if address[0] == "stack":
            if address[1] >= 0:
                raise ValueError("write to caller stack")
            stack[address[1]] = value
            return
        if address[0] != "arg" or value is None or value[0] != "value":
            raise ValueError("store is not a global-to-output copy")
        key = (address[1], address[2])
        if key in stores or key[1] not in range(0, word * components, word):
            raise ValueError("duplicate or out-of-range output store")
        stores[key] = value

    for instruction in code:
        if returned:
            raise ValueError("instructions after return")
        mnemonic = instruction["mnem"]
        operands = instruction["ops"]
        site = instruction.get("site")
        if mnemonic == "picbase":
            if stores or floating:
                raise ValueError("late PIC prologue")
            registers[operands[0]["name"]] = ("ptr", operands[1]["value"], None)
        elif mnemonic in ("mov", "movss"):
            write(operands[0], read(operands[1], site))
        elif mnemonic == "lea":
            address = effective(operands[1])
            if address[0] != "ptr" or not writable(address[1]) or not operands[1].get("disp32") or site is None:
                raise ValueError("unsupported address materialization")
            write(operands[0], ("ptr", address[1], site))
        elif mnemonic == "fld":
            value = read(operands[0], site)
            if value is None or value[0] != "value" or len(floating) >= 8:
                raise ValueError("unsupported x87 load")
            floating.append(value)
        elif mnemonic == "fstp":
            if not floating:
                raise ValueError("x87 stack underflow")
            write(operands[0], floating.pop())
        elif mnemonic == "push":
            value = read(operands[0], site)
            sp = registers["esp"][1] - word
            registers["esp"] = ("stack", sp, None)
            stack[sp] = value
        elif mnemonic == "pop":
            sp = registers["esp"][1]
            write(operands[0], stack.get(sp))
            registers["esp"] = ("stack", sp + word, None)
        elif mnemonic in ("add", "sub"):
            if operands[0] != {"kind": "reg", "name": "esp", "width": word} or operands[1]["kind"] != "imm":
                raise ValueError("unsupported arithmetic")
            delta = operands[1]["value"] * (1 if mnemonic == "add" else -1)
            registers["esp"] = ("stack", registers["esp"][1] + delta, None)
        elif mnemonic in ("ret", "retn"):
            if operands or floating or registers["esp"] != ("stack", 0, None):
                raise ValueError("unbalanced return")
            returned = True
        elif mnemonic != "nop":
            raise ValueError("unsupported instruction: " + mnemonic)
    if not returned or len(stores) != arguments * components:
        raise ValueError("incomplete vector copies")
    found = []
    for argument in range(arguments):
        values = [stores[(argument, offset)] for offset in range(0, word * components, word)]
        base = values[0][1]
        if any(value[1] != base + index * word for index, value in enumerate(values)):
            raise ValueError("noncontiguous vector source")
        found.append({"gv_ea": hex(base), **values[0][2]})
    bases = [int(item["gv_ea"], 0) for item in found]
    if any(abs(a - b) < word * components for i, a in enumerate(bases) for b in bases[i + 1 :]):
        raise ValueError("overlapping vector sources")
    return found


WALK = (
    inspect.getsource(recover_vectors)
    + r"""
import re

def decode_view_info(owner):
    fn = ida_funcs.get_func(owner)
    if fn is None or fn.start_ea != owner or idaapi.inf_is_64bit():
        raise ValueError('expected x86 function entry')
    ranges = [(s.start_ea, s.end_ea) for s in
              (ida_segment.getseg(ea) for ea in idautils.Segments())
              if is_writable_data(s.start_ea)]
    code, slots = [], {}
    items = list(idautils.FuncItems(owner))
    skip = set()
    for index, ea in enumerate(items):
        if ea in skip:
            continue
        insn = idautils.DecodeInstruction(ea)
        if not insn:
            raise ValueError('undecodable instruction')
        mnem = (idc.print_insn_mnem(ea) or '').lower()
        if mnem == 'call':
            # Only the exact get-PC thunk is accepted, before the copy body.
            if index != 0 or len(items) < 2:
                raise ValueError('unexpected call')
            callee = idc.get_operand_value(ea, 0)
            thunk = ida_bytes.get_bytes(callee, 4)
            following = idautils.DecodeInstruction(items[1])
            if not thunk or thunk[0:2] != b'\x8b\x04' or thunk[2:] != b'\x24\xc3':
                raise ValueError('not the eax get-PC thunk')
            if (idc.print_insn_mnem(items[1]) != 'add' or reg4(following.ops[0]) != 'eax'
                    or following.ops[1].type != idaapi.o_imm):
                raise ValueError('invalid GOT prologue')
            got = (items[1] + following.ops[1].value) & 0xFFFFFFFF
            if not is_got(got):
                raise ValueError('PIC base does not name GOT')
            code.append({'mnem': 'picbase', 'ops': [
                {'kind': 'reg', 'name': 'eax', 'width': 4}, {'kind': 'imm', 'value': got}]})
            skip.add(items[1])
            continue
        ops = []
        site = None
        for operand_index, op in enumerate(insn.ops):
            kind = int(op.type)
            if kind == idaapi.o_void:
                break
            # IDA adds implicit x87 stack operands. FLD/FSTP stack effects
            # are modeled by the interpreter, not as explicit operands.
            if mnem in ('fld', 'fstp') and not op.shown():
                continue
            width = ida_ua.get_dtype_size(op.dtype)
            if kind == idaapi.o_reg:
                # IDA reports the whole 128-bit XMM register; MOVSS transfers
                # only its low float32 lane, whose provenance is tracked here.
                if mnem == 'movss' and (reg4(op) or '').startswith('xmm'):
                    width = 4
                ops.append({'kind': 'reg', 'name': reg4(op), 'width': width})
            elif kind == idaapi.o_imm:
                ops.append({'kind': 'imm', 'value': int(op.value)})
            elif kind in (idaapi.o_mem, idaapi.o_phrase, idaapi.o_displ):
                text = (idc.print_operand(ea, operand_index) or '').lower()
                if 'fs:' in text or 'gs:' in text or '*' in text:
                    raise ValueError('unsupported segment or indexed operand')
                base = None
                if kind != idaapi.o_mem:
                    bracket = re.search(r'\[([^\]]+)\]', text)
                    names = re.findall(r'\b(?:eax|ecx|edx|ebx|esp|ebp|esi|edi)\b', bracket.group(1) if bracket else '')
                    if len(names) != 1:
                        raise ValueError('memory operand needs one base register')
                    base = names[0]
                offset = int(op.addr) if kind == idaapi.o_mem else signed32(op.addr) if kind == idaapi.o_displ else 0
                offb = int(op.offb)
                disp32 = bool(offb and insn.size - offb >= 4)
                ops.append({'kind': 'mem', 'base': base, 'offset': offset, 'width': width, 'disp32': disp32})
                if disp32:
                    if site is not None:
                        raise ValueError('multiple address operands')
                    site = {'insn_ea': hex(ea), 'insn_len': hex(insn.size), 'insn_disp': hex(offb)}
            else:
                raise ValueError('unsupported operand at %x: %s operand %d type %d' % (ea, mnem, operand_index, kind))
        for ref in idautils.DataRefsFrom(ea):
            if is_got(ref):
                slots[int(ref)] = int(ida_bytes.get_dword(ref))
        code.append({'mnem': mnem, 'ops': ops, 'site': site})
    return recover_vectors(code, ranges, slots)

result = {'pointer_size': 4, 'vectors': decode_view_info(int(values['owner']))}
"""
)


async def locate_vectors(session, owner):
    return await run_walk(session, WALK, {"owner": int(owner)})
