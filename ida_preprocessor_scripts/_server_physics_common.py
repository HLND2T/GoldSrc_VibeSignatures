"""Current-instruction evidence for the engine's private physics globals.

No build addresses, server member offsets or call ordinals are locators.
Frame clamps identify the double written by Host_FilterTime; indexed model
loads prove their own table width and upper bound. The same probes are used
to check the LLM-selected globals against the current IDB.
"""

from ida_analyze_util import (
    _INSPECT_FUNCTION_PY_EVAL,
    _find_unique_bytes,
    _load_yaml_mapping,
    _output_for_symbol,
    parse_mcp_result,
    write_func_yaml,
    write_gv_yaml,
)
from ida_preprocessor_scripts._engine_private_globals_common import run_walk
from ida_preprocessor_scripts._native_rcon_globals_common import GLOBAL_PY
from ida_preprocessor_scripts.renderer_elf_symbols import STT_FUNC, current_elf_symbols, preserve_global_identities

MODEL_SIB_PY = r"""
def indexed_model_access(start, server):
    got_base, got_reg = got_anchor(start)
    bases = {} if got_base is None else {got_reg: got_base}
    matches = []
    for entry in scan(start) or []:
        insn, mnem = entry['insn'], entry['mnem']
        raw = ida_bytes.get_bytes(entry['ea'], int(insn.size))
        if mnem in ('mov', 'push') and '*4' in entry['disasm']:
            for op in insn.ops:
                displacement = int(getattr(op, 'offb', 0))
                if int(op.type) not in (int(idaapi.o_mem), int(idaapi.o_displ)) or displacement < 2 or displacement + 4 > len(raw):
                    continue
                # Decode the current ModRM/SIB, not a string-like IDA label
                # for a member displacement or a guessed base register.
                modrm, sib = raw[displacement - 2], raw[displacement - 1]
                if modrm & 7 != 4 or sib >> 6 != 2 or (sib >> 3) & 7 == 4:
                    continue
                register = (ida_idp.get_reg_name(sib & 7, 4) or '').lower()
                absolute = modrm >> 6 == 0 and sib & 7 == 5
                base = 0 if absolute else bases.get(register)
                if base is None or ida_ua.get_dtype_size(op.dtype) != 4:
                    continue
                encoded = int.from_bytes(raw[displacement:displacement + 4], 'little')
                address = (base + encoded) & 0xffffffff
                if is_writable_data(address) and address > server:
                    matches.append((entry, address, displacement, encoded, not absolute))
        dst, src = insn.ops[0], insn.ops[1]
        if int(dst.type) == int(idaapi.o_reg) and changed_operand(insn, 0):
            register = reg4(dst)
            if register == got_reg:
                continue
            incoming = None
            if mnem == 'mov' and int(src.type) == int(idaapi.o_reg):
                incoming = bases.get(reg4(src))
            elif mnem in ('mov', 'lea') and int(src.type) in (int(idaapi.o_mem), int(idaapi.o_displ)):
                address = int(src.addr) if int(src.type) == int(idaapi.o_mem) else (
                    (bases[reg4(src)] + signed32(src.addr)) & 0xffffffff if reg4(src) in bases else None)
                if address is not None:
                    if mnem == 'lea' and is_writable_data(address):
                        incoming = address
                    elif mnem == 'mov' and is_got(address):
                        pointee = int(ida_bytes.get_dword(address))
                        if is_writable_data(pointee):
                            incoming = pointee
            elif mnem == 'mov' and int(src.type) == int(idaapi.o_imm) and is_writable_data(src.value):
                incoming = int(src.value)
            bases.pop(register, None)
            if incoming is not None:
                bases[register] = incoming
    if len(matches) != 1:
        raise ValueError('model-indexed table access is not unique/resolved: '+str(len(matches)))
    return matches[0]
"""

FUNCTION_SYMBOLS = {
    "ModelFrames": "_Z11ModelFramesi",
    "SV_LinkEdict": "_Z12SV_LinkEdictP7edict_si",
    "SV_LinkContents": "_Z15SV_LinkContentsP10areanode_sPKf",
    "Host_FilterTime": "_Z15Host_FilterTimef",
}


async def preserve_functions(session, outputs, platform, image_base, names):
    if platform != "linux":
        return True
    symbols = await current_elf_symbols(session, list(names) + [FUNCTION_SYMBOLS[n] for n in names])
    for name in names:
        output = _output_for_symbol(outputs, name)
        data = _load_yaml_mapping(output)
        matches = {
            symbol
            for symbol, value, kind in symbols
            if kind == STT_FUNC and value + int(image_base) == int(data["func_va"], 0)
        }
        if len(matches) > 1:
            return False
        if matches:
            data["func_name"] = matches.pop()
            write_func_yaml(output, data)
    return True


async def finish_globals(session, outputs, platform):
    """Publish a unique signature beginning at each already validated access."""
    for output in outputs:
        data = _load_yaml_mapping(output)
        if not data or "gv_va" not in data:
            return False
        instruction = int(data["gv_sig_va"], 0) + int(data["gv_inst_offset"], 0)
        owner = int(data["gv_sig_va"], 0)
        for across in (False, True):
            source = (
                _INSPECT_FUNCTION_PY_EVAL.replace("EA_PLACEHOLDER", str(owner))
                .replace("IMAGE_BASE_PLACEHOLDER", "0")
                .replace("ALLOW_ACROSS_FUNCTION_BOUNDARY_PLACEHOLDER", str(across))
            )
            source += f"\nresult=json.dumps({{'signature': _signature({instruction}, int(func.end_ea)) if func is not None else None}})"
            located = parse_mcp_result(await session.call_tool("py_eval", {"code": source}))
            signature = located.get("signature") if isinstance(located, dict) else None
            disp = int(data["gv_inst_disp"], 0)
            if not signature or signature.split()[disp : disp + 4] != ["??"] * 4:
                continue
            if await _find_unique_bytes(session, signature) == instruction:
                break
        else:
            return False
        data.update(gv_sig=signature, gv_sig_va=hex(instruction), gv_inst_offset="0x0")
        data.pop("gv_sig_allow_across_function_boundary", None)
        if across:
            data["gv_sig_allow_across_function_boundary"] = True
        write_gv_yaml(output, data)
    return await preserve_global_identities(session, outputs, platform)


FRAME_PY = r"""
import struct, re, ida_lines

def float_constant(entry, operand):
    op = entry['insn'].ops[operand]
    # IDA may expose the implicit x87 stack operand before the memory read.
    if entry['mnem'].startswith('f'):
        op = next((item for item in entry['insn'].ops
                   if int(item.type) in (int(idaapi.o_mem), int(idaapi.o_displ))), op)
    if int(op.type) not in (int(idaapi.o_mem), int(idaapi.o_displ)):
        return None
    width = ida_ua.get_dtype_size(op.dtype)
    if width not in (4, 8):
        return None
    refs = list(idautils.DataRefsFrom(entry['ea']))
    if int(op.type) == int(idaapi.o_mem):
        refs.append(int(op.addr))
    found = set()
    for ref in refs:
        if not is_readable_data(ref) or is_writable_data(ref):
            continue
        raw = ida_bytes.get_bytes(ref, width)
        if raw:
            value = struct.unpack('<f' if width == 4 else '<d', raw)[0]
            if 0 < value < 1:
                found.add(value)
    return next(iter(found)) if len(found) == 1 else None

def frame_clamps(start):
    registers = {}
    stack = [None] * 8
    found = {}
    entries = scan(start) or []
    # MSVC stores literal doubles as two adjacent immediate dword writes.
    # Reconstruct their bits and require a genuine 8-byte access to that base.
    wide = {gv for e in entries for gv in e['targets']
            if any(ida_ua.get_dtype_size(op.dtype) == 8 for op in e['insn'].ops
                   if int(op.type) in (int(idaapi.o_mem), int(idaapi.o_displ)))}
    for first, second in zip(entries, entries[1:]):
        if first['mnem'] != 'mov' or second['mnem'] != 'mov':
            continue
        if len(first['written']) != 1 or len(second['written']) != 1:
            continue
        lo, hi = first['insn'].ops[1], second['insn'].ops[1]
        if int(lo.type) != int(idaapi.o_imm) or int(hi.type) != int(idaapi.o_imm):
            continue
        gv = next(iter(first['written']))
        if gv not in wide or next(iter(second['written'])) != gv + 4:
            continue
        value = struct.unpack('<d', struct.pack('<II', int(lo.value) & 0xffffffff, int(hi.value) & 0xffffffff))[0]
        if 0 < value < 1:
            found.setdefault(gv, []).append((first, value))
    for entry in entries:
        insn, mnem = entry['insn'], entry['mnem']
        dst, src = insn.ops[0], insn.ops[1]
        def st_index(index):
            # Hidden x87 operands shift IDA operand indexes. The rendered
            # operand is the explicit stack position (or a memory address).
            line = ida_lines.tag_remove(entry['disasm']).split(';', 1)[0].strip()
            fields = line.split(None, 1)
            args = fields[1].split(',') if len(fields) == 2 else []
            text = args[index].strip() if index < len(args) else ''
            match = re.fullmatch(r'st(?:\((\d)\))?', text)
            return int(match.group(1) or 0) if match else None
        if mnem == 'fld':
            source_index = st_index(0)
            constant = stack[source_index] if source_index is not None else float_constant(entry, 0)
            stack = [constant] + stack[:7]
        elif mnem == 'fxch':
            index = st_index(0)
            if index is None:
                index = 1
            stack[0], stack[index] = stack[index], stack[0]
        elif mnem in ('fst', 'fstp'):
            memory = next((op for op in insn.ops if int(op.type) in (int(idaapi.o_mem), int(idaapi.o_displ))), None)
            if stack[0] is not None and len(entry['written']) == 1 and memory is not None and ida_ua.get_dtype_size(memory.dtype) == 8:
                gv = next(iter(entry['written']))
                found.setdefault(gv, []).append((entry, stack[0]))
            index = st_index(0)
            if index is not None:
                stack[index] = stack[0]
            if mnem == 'fstp':
                stack = stack[1:] + [None]
        elif mnem in ('fucomip', 'fcomip', 'fcomp', 'fucomp'):
            stack = stack[1:] + [None]
        elif mnem in ('fcompp', 'fucompp'):
            stack = stack[2:] + [None, None]
        elif mnem in ('movsd', 'movss', 'movapd', 'movaps'):
            if int(dst.type) == int(idaapi.o_reg):
                name = idc.print_operand(entry['ea'], 0)
                registers.pop(name, None)
                constant = float_constant(entry, 1)
                if int(src.type) == int(idaapi.o_reg):
                    constant = registers.get(idc.print_operand(entry['ea'], 1))
                if constant is not None:
                    registers[name] = constant
            elif len(entry['written']) == 1 and mnem == 'movsd':
                constant = registers.get(idc.print_operand(entry['ea'], 1))
                if constant is not None:
                    gv = next(iter(entry['written']))
                    found.setdefault(gv, []).append((entry, constant))
        else:
            for index, op in enumerate(insn.ops):
                if int(op.type) == int(idaapi.o_void):
                    break
                if int(op.type) == int(idaapi.o_reg) and changed_operand(insn, index):
                    registers.pop(idc.print_operand(entry['ea'], index), None)
            if mnem.startswith('f') and mnem not in ('fnstsw', 'fcom', 'fucom', 'fucomi', 'fcomi'):
                stack[0] = None
        if mnem == 'call':
            stack = [None] * 8
            registers.clear()
    return found
"""

HOST_WALK = (
    FRAME_PY
    + r"""
literal_owner = exact_string_owner('-sys_ticrate')
if literal_owner is not None:
    candidates = {literal_owner}
else:
    candidates = set(direct_calls(int(values['frame'])))
valid = {}
for candidate in sorted(candidates):
    clamps = frame_clamps(candidate)
    if len(clamps) == 1:
        valid[candidate] = clamps
if len(valid) != 1:
    result = {'error': 'frame filter/clamped double is not unique', 'candidates': [hex(e) for e in valid]}
else:
    start = next(iter(valid))
    gv = next(iter(valid[start]))
    entry, upper = max(valid[start][gv], key=lambda item: item[1])
    result = {'owner': hex(start), 'gv': access(entry, gv), 'clamps': [v for _, v in valid[start][gv]]}
"""
)


async def locate_host(session, frame):
    return await run_walk(session, HOST_WALK, {"frame": frame})


LAYOUT_PY = (
    GLOBAL_PY
    + MODEL_SIB_PY
    + r"""
def immediate(entry, operand=1):
    op = entry['insn'].ops[operand]
    return int(op.value) if int(op.type) == int(idaapi.o_imm) else None

def one(items, role):
    if len(items) != 1:
        raise ValueError('ambiguous ' + role + ': ' + repr(items))
    return next(iter(items))

def node_fields(start, root=None):
    import ida_gdl
    function = ida_funcs.get_func(start)
    blocks = list(ida_gdl.FlowChart(function))
    entry_block = one({block.id for block in blocks if block.start_ea == start}, 'node function entry block')
    instructions = {item['ea']: item for item in scan(start) or []}

    def process(block, incoming):
        state = dict(incoming)
        fields = {'axis': set(), 'dist': set(), 'children': set(), 'heads': set()}
        for ea in idautils.Heads(block.start_ea, block.end_ea):
            entry = instructions.get(ea)
            if entry is None:
                continue
            insn, mnem = entry['insn'], entry['mnem']
            dst, src = insn.ops[0], insn.ops[1]
            bias, frame = state.get('$sp', 0), state.get('$fp')
            def stack_key(op):
                if int(op.type) != int(idaapi.o_displ):
                    return None
                origin = bias if reg4(op) == 'esp' else frame if reg4(op) == 'ebp' else None
                return None if origin is None else ('stack', origin + signed32(op.addr))
            def read(op):
                if int(op.type) == int(idaapi.o_reg):
                    return state.get(reg4(op))
                key = stack_key(op)
                if key is not None:
                    if root is None and key[1] == 4:
                        return ('node', 0)
                    return state.get(key)
                if int(op.type) in (int(idaapi.o_phrase), int(idaapi.o_displ)):
                    pointer = state.get(reg4(op))
                    if pointer and pointer[0] == 'node':
                        offset = pointer[1] + (signed32(op.addr) if int(op.type) == int(idaapi.o_displ) else 0)
                        return ('field', offset)
                    if pointer and pointer[0] == 'field' and pointer[1] > 0:
                        # Debug builds spill a loaded child pointer, then use
                        # it as the base of the next node access. Observe that
                        # dereference before treating the field as a pointer.
                        fields['children'].add(pointer[1])
                        offset = signed32(op.addr) if int(op.type) == int(idaapi.o_displ) else 0
                        return ('field', offset)
                return None
            result = None
            source = read(src)
            if mnem == 'cmp' and int(src.type) == int(idaapi.o_imm) and int(src.value) & 0xffffffff == 0xffffffff:
                target = read(dst)
                if target and target[0] == 'field':
                    fields['axis'].add(target[1])
            for op in insn.ops:
                if int(op.type) == int(idaapi.o_void):
                    break
                target = read(op)
                if target and target[0] == 'field' and mnem in ('fld', 'fcomp', 'comiss', 'ucomiss', 'movss') and ida_ua.get_dtype_size(op.dtype) == 4:
                    fields['dist'].add(target[1])
            if mnem == 'mov':
                result = source
                if source and source[0] == 'field' and source[1] > 0 and int(dst.type) == int(idaapi.o_reg):
                    # Traversal keeps the node pointer in the same register.
                    if reg4(dst) == reg4(src):
                        fields['children'].add(source[1])
                        result = ('node', 0)
            elif mnem == 'lea' and source and source[0] == 'field':
                result = ('node', source[1])
                if source[1] > 0:
                    fields['heads'].add(source[1])
            elif mnem in ('add', 'sub') and int(src.type) == int(idaapi.o_imm):
                prior = read(dst)
                if prior and prior[0] == 'node':
                    offset = prior[1] + (1 if mnem == 'add' else -1) * signed32(src.value)
                    result = ('node', offset)
                    if offset > 0:
                        fields['heads'].add(offset)
            if root is not None and root in entry['targets'] and mnem in ('mov', 'lea'):
                if mnem == 'lea' or int(src.type) == int(idaapi.o_imm) or any(is_got(r) for r in idautils.DataRefsFrom(ea)):
                    result = ('node', 0)
                elif mnem == 'mov':
                    result = ('field', 0)
            if mnem == 'mov':
                key = stack_key(dst)
                if key is not None:
                    if state.get(key) == ('node', 0) and result and result[0] == 'field' and result[1] > 0:
                        fields['children'].add(result[1])
                        result = ('node', 0)
                    state.pop(key, None)
                    if result is not None:
                        state[key] = result
            # Compiler padding such as xchg ax,ax leaves the pointer unchanged.
            same_register = (mnem == 'xchg' and int(dst.type) == int(idaapi.o_reg)
                             and int(src.type) == int(idaapi.o_reg) and reg4(dst) == reg4(src))
            for index, op in enumerate(insn.ops):
                if int(op.type) == int(idaapi.o_void):
                    break
                if int(op.type) == int(idaapi.o_reg) and changed_operand(insn, index) and not same_register:
                    state.pop(reg4(op), None)
            if int(dst.type) == int(idaapi.o_reg) and result is not None:
                state[reg4(dst)] = result
            if mnem == 'mov' and reg4(dst) == 'ebp' and int(src.type) == int(idaapi.o_reg) and reg4(src) == 'esp':
                state['$fp'] = bias
            if mnem == 'push':
                state['$sp'] = bias - 4
            elif mnem == 'pop':
                state['$sp'] = bias + 4
            elif mnem in ('add', 'sub') and reg4(dst) == 'esp' and int(src.type) == int(idaapi.o_imm):
                state['$sp'] = bias + (1 if mnem == 'add' else -1) * int(src.value)
            if mnem == 'call':
                for reg in ('eax', 'ecx', 'edx'):
                    state.pop(reg, None)
        return state, fields

    inputs, outputs = {entry_block: {'$sp': 0}}, {}
    for iteration in range(len(blocks) * 4 + 1):
        changed = False
        for block in blocks:
            if block.id != entry_block:
                parents = [outputs[p.id] for p in block.preds() if p.id in outputs]
                if not parents:
                    continue
                merged = {key: value for key, value in parents[0].items()
                          if all(parent.get(key) == value for parent in parents[1:])}
                inputs[block.id] = merged
            state, _ = process(block, inputs[block.id])
            if outputs.get(block.id) != state:
                outputs[block.id] = state
                changed = True
        if not changed:
            break
    else:
        raise ValueError('node pointer dataflow did not converge')
    fields = {'axis': set(), 'dist': set(), 'children': set(), 'heads': set()}
    for block in blocks:
        if block.id in inputs:
            _, observed = process(block, inputs[block.id])
            for name, offsets in observed.items():
                fields[name].update(offsets)
    return fields

def model_layout(start, models, server):
    entries = scan(start) or []
    _, observed_models, _, _, _ = indexed_model_access(start, server)
    if observed_models != models:
        raise ValueError('model global is not the guarded four-byte indexed table in ModelFrames')
    limits = set()
    for index, entry in enumerate(entries[:-1]):
        insn = entry['insn']
        if entry['mnem'] != 'cmp' or int(insn.ops[1].type) != int(idaapi.o_imm):
            continue
        limit = int(insn.ops[1].value)
        if limit < 256:
            continue
        jump = entries[index + 1]['mnem']
        if jump in ('ja', 'jbe'):
            # Validate the index-minus-one normalization in the current body.
            reg = reg4(insn.ops[0])
            normalized = any(e['mnem'] == 'lea' and reg4(e['insn'].ops[0]) == reg
                             and signed32(e['insn'].ops[1].addr) == -1 for e in entries[:index])
            if normalized:
                limits.add(limit + 2)
        elif jump in ('jge', 'jl'):
            limits.add(limit)
    capacity = one(limits, 'model capacity')
    offset = models - server
    if offset < 0 or offset % 4 or not is_writable_data(models + capacity * 4 - 1):
        raise ValueError('models are not a mapped aligned sv member array')
    return {'sv_models_offset': offset, 'sv_models_element_size': 4,
            'sv_models_count': capacity, 'sv_models_size': capacity * 4}

def group_setter(mask, operation):
    candidates = set()
    for target in (mask, operation):
        for ref in idautils.DataRefsTo(target):
            func = ida_funcs.get_func(ref)
            if func is not None and not is_plt(func.start_ea):
                candidates.add(int(func.start_ea))
    valid = set()
    for start in candidates:
        entries = scan(start) or []
        stores = {gv for entry in entries for gv in entry['written']}
        if not {mask, operation}.issubset(stores):
            continue
        registers = {}
        bias = 0
        frame = None
        assigned = {}
        for entry in entries:
            insn, mnem = entry['insn'], entry['mnem']
            dst, src = insn.ops[0], insn.ops[1]
            if mnem == 'push':
                bias -= 4
            elif mnem == 'pop':
                bias += 4
            elif mnem in ('add', 'sub') and reg4(dst) == 'esp' and int(src.type) == int(idaapi.o_imm):
                bias += (1 if mnem == 'add' else -1) * int(src.value)
            elif mnem == 'mov' and reg4(dst) == 'ebp' and int(src.type) == int(idaapi.o_reg) and reg4(src) == 'esp':
                frame = bias
            if mnem == 'mov' and int(dst.type) == int(idaapi.o_reg):
                incoming = None
                if int(src.type) == int(idaapi.o_reg):
                    incoming = registers.get(reg4(src))
                elif int(src.type) == int(idaapi.o_displ):
                    origin = bias if reg4(src) == 'esp' else frame if reg4(src) == 'ebp' else None
                    if origin is not None:
                        incoming = origin + signed32(src.addr)
                registers.pop(reg4(dst), None)
                if incoming is not None:
                    registers[reg4(dst)] = incoming
            elif mnem == 'mov' and int(src.type) == int(idaapi.o_reg) and len(entry['written']) == 1:
                target = next(iter(entry['written']))
                if target in (mask, operation) and ida_ua.get_dtype_size(dst.dtype) == 4:
                    assigned[target] = registers.get(reg4(src))
            elif mnem not in ('cmp', 'test', 'push', 'pop', 'ret', 'retn'):
                for index, op in enumerate(insn.ops):
                    if int(op.type) == int(idaapi.o_reg) and changed_operand(insn, index):
                        registers.pop(reg4(op), None)
        if assigned == {mask: 4, operation: 8}:
            valid.add(start)
    return one(valid, 'PF_SetGroupMask(mask, op) setter')

def node_storage(root, stride):
    owners = set()
    for ref in idautils.DataRefsTo(root):
        function = ida_funcs.get_func(ref)
        if function is not None:
            owners.add(int(function.start_ea))
    sizes = set()
    for owner in owners:
        for target, args in call_arguments(owner):
            if args[0] == ('address', root) and args[1] == ('constant', 0) and args[2] is not None and args[2][0] == 'constant':
                size = args[2][1]
                if size > stride and size % stride == 0:
                    sizes.add(size)
    size = one(sizes, 'sv_areanodes clear size')
    return {'sv_areanodes_size': size, 'sv_areanodes_count': size // stride,
            'sv_areanodes_element_size': stride}
"""
)

LAYOUT_WALK = (
    LAYOUT_PY
    + r"""
owners, globals = values['owners'], values['globals']
scalars = model_layout(owners['ModelFrames'], globals['sv_models'], globals['sv'])
setter = group_setter(globals['g_groupmask'], globals['g_groupop'])
content = node_fields(owners['SV_LinkContents'])
linked = node_fields(owners['SV_LinkEdict'], globals['sv_areanodes'])
axis = one(content['axis'] | linked['axis'], 'areanode axis offset')
dist = one(content['dist'] | linked['dist'], 'areanode dist offset')
heads = sorted(linked['heads'])
children = sorted(offset for offset in content['children'] | linked['children']
                  if heads and offset < heads[0])
if len(children) != 2 or children[1] != children[0] + 4 or len(heads) != 2 or heads[1] != heads[0] + 8:
    raise ValueError('incomplete area node traversal/list layout: '+repr((content, linked)))
if one(content['heads'], 'SV_LinkContents solid-edict list head') != heads[1]:
    raise ValueError('contents traversal disagrees with the solid-edict list head')
members = {'axis': (axis, 4), 'dist': (dist, 4), 'children': (children[0], 8),
           'trigger_edicts': (heads[0], 8), 'solid_edicts': (heads[1], 8)}
stride = heads[1] + 8
if axis != 0 or dist != axis + 4 or children[0] != dist + 4 or heads[0] != children[1] + 4:
    raise ValueError('area node fields do not form the observed packed x86 layout')
scalars.update(node_storage(globals['sv_areanodes'], stride))
result = {'scalars': scalars, 'members': members, 'group_setter': hex(setter),
          'evidence': {'contents': {k: sorted(v) for k,v in content.items()},
                       'linked': {k: sorted(v) for k,v in linked.items()}}}
"""
)
