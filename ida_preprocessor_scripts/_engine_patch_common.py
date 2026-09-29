"""Decoded x86 call dataflow shared by engine patch locators.

Execute inside the owned worker after the engine decoder. No IDA symbol names
participate: constants, frame addresses and global loads are operand-derived.
"""

import inspect

from ida_preprocessor_scripts import x86_call_arguments


CALL_FLOW_PY = (
    inspect.getsource(x86_call_arguments)
    + r"""
import ida_frame, ida_gdl

MAX_PATH_INSTRUCTIONS = 128
X86_REGISTERS = ('eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'esp', 'ebp')


def frame_operand(entry, index, sp):
    op = entry['insn'].ops[index]
    kind = int(op.type)
    if kind not in (int(idaapi.o_displ), int(idaapi.o_phrase)):
        return None
    text = (idc.print_operand(entry['ea'], index) or '').lower()
    registers = [reg for reg in X86_REGISTERS if reg in text]
    displacement = signed32(op.addr) if kind == int(idaapi.o_displ) else 0
    if registers == ['esp']:
        return ('stack', sp + displacement)
    if registers == ['ebp']:
        return ('frame', displacement)
    return None


def decoded_calls(owner, entries):
    function = ida_funcs.get_func(owner)
    got_base, got_register = got_anchor(owner)
    code = []
    for entry in entries:
        sp = int(ida_frame.get_spd(function, entry['ea']))
        operands = []
        mnem = entry['mnem']
        for index, op in enumerate(entry['insn'].ops):
            kind = int(op.type)
            if kind == int(idaapi.o_void):
                break
            operand = ('unknown', None)
            if kind == int(idaapi.o_reg):
                operand = ('reg', reg4(op))
            elif kind == int(idaapi.o_imm):
                operand = ('imm', int(op.value) & 0xFFFFFFFF)
            elif kind == int(idaapi.o_near):
                operand = ('imm', int(op.addr))
            else:
                frame = frame_operand(entry, index, sp)
                if frame is not None:
                    operand = frame
                elif kind == int(idaapi.o_mem):
                    operand = ('imm', ('global_value', int(op.addr)))
            operands.append(operand)
        if mnem == 'lea' and len(operands) == 2:
            source = entry['insn'].ops[1]
            frame = frame_operand(entry, 1, sp)
            address = None
            if frame is not None:
                address = ('local_address', *frame)
            elif int(source.type) == int(idaapi.o_mem):
                address = int(source.addr)
            elif int(source.type) == int(idaapi.o_displ) and got_base is not None and reg4(source) == got_register:
                address = (got_base + signed32(source.addr)) & 0xFFFFFFFF
            if address is not None:
                mnem, operands[1] = 'mov', ('imm', address)
        if operands and operands[0][0] in ('reg', 'stack', 'frame'):
            width = ida_ua.get_dtype_size(entry['insn'].ops[0].dtype)
            if width != 4 and mnem not in ('cmp', 'test', 'push'):
                mnem = 'unknown_write'
        code.append({'ea': entry['ea'], 'mnem': mnem, 'ops': operands, 'sp': sp})
    return code


def anchored_call_path(owner, code, anchor):
    # Follow the literal's path, including compiler-shared copy tails. This is
    # deliberately path-specific: the same call may also copy a Steam language.
    blocks = [b for b in ida_gdl.FlowChart(ida_funcs.get_func(owner)) if b.start_ea <= anchor < b.end_ea]
    if len(blocks) != 1:
        return None
    by_ea = {item['ea']: index for index, item in enumerate(code)}
    index = by_ea.get(int(blocks[0].start_ea))
    visited = set()
    path = []
    seen_anchor = False
    while index is not None and index < len(code) and len(visited) < MAX_PATH_INSTRUCTIONS:
        item = code[index]
        if index in visited:
            return None
        visited.add(index)
        seen_anchor |= item['ea'] == anchor
        mnem = item['mnem']
        if mnem == 'call':
            return path + [item] if seen_anchor else None
        if mnem == 'jmp':
            operands = item['ops']
            index = by_ea.get(operands[0][1]) if operands and operands[0][0] == 'imm' else None
            continue
        if mnem.startswith('j') or mnem.startswith('ret') or mnem.startswith('loop'):
            return None
        path.append(item)
        index += 1
    return None


def owner_strings(entries):
    found = set()
    for entry in entries:
        for ref in idautils.DataRefsFrom(entry['ea']):
            value = ida_bytes.get_strlit_contents(ref, -1, ida_nalt.STRTYPE_C)
            if value:
                found.add(value.decode('utf-8', errors='replace'))
    return found
"""
)


def language_role(arguments, strings, literal_eas):
    """Require the language buffer ABI and filesystem search-path ownership."""
    if len(arguments) != 3:
        return None
    destination, source, size = arguments
    if not isinstance(destination, tuple) or destination[0] != "local_address":
        return None
    if source not in literal_eas or size != 128:
        return None
    if "%s/%s_%s" not in strings or "GAME" not in strings:
        return None
    return (
        "FileSystem_SetGameDirectory_V_strncpy_callsite_0"
        if "DEFAULTGAME" in strings
        else "FileSystem_AddFallbackGameDir_V_strncpy_callsite_0"
    )


def factory_origin(code, query_index):
    """Trace an indirect interface query back to its dominating factory call."""
    graph = x86_call_arguments._control_flow(code)

    def origin(before, operand):
        if operand[0] not in ("reg", "stack", "frame"):
            return None
        for index in range(before - 1, -1, -1):
            item = code[index]
            operands = item["ops"]
            mnem = item["mnem"]
            if mnem == "call":
                if operand == ("reg", "eax"):
                    return index
                if operand[0] == "reg" and operand[1] in x86_call_arguments.CALLER_SAVED:
                    return None
            if operands and operands[0] == operand and mnem not in ("cmp", "test", "push", "call"):
                if x86_call_arguments._may_reach(graph, 0, before, blocked=index):
                    return None
                return origin(index, operands[1]) if mnem == "mov" and len(operands) == 2 else None
        return None

    query = code[query_index]
    if query["mnem"] != "call" or not query["ops"]:
        return None
    index = origin(query_index, query["ops"][0])
    if index is None or x86_call_arguments._may_reach(graph, 0, query_index, blocked=index):
        return None
    return index
