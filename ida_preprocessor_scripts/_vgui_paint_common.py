"""Current-binary RTTI and x86 dataflow support for the VGUI paint chain."""

from pathlib import Path

import ida_preprocessor_scripts._x86_vcall_flow as x86_vcall_flow
from ida_analyze_util import _inspect_function_via_mcp, _load_yaml_mapping, _output_for_symbol, write_func_yaml
from ida_preprocessor_scripts._engine_private_globals_common import run_walk


FLOW_SOURCE = Path(x86_vcall_flow.__file__).read_text(encoding="utf-8")

IDA_FLOW = r"""
import ida_frame, ida_gdl

def flow_register(op):
    name = ida_idp.get_reg_name(int(op.reg), ida_ua.get_dtype_size(op.dtype)) or ''
    aliases = {'al':'eax','ah':'eax','ax':'eax','bl':'ebx','bh':'ebx','bx':'ebx',
               'cl':'ecx','ch':'ecx','cx':'ecx','dl':'edx','dh':'edx','dx':'edx',
               'si':'esi','di':'edi','bp':'ebp','sp':'esp'}
    return aliases.get(name,name)

def decoded_operand(op):
    kind = int(op.type)
    if kind == idaapi.o_reg:
        if ida_idp.get_reg_name(int(op.reg), ida_ua.get_dtype_size(op.dtype)) in ('ah','bh','ch','dh'):
            return ('reg', flow_register(op), 1, 8)
        return ('reg', flow_register(op), ida_ua.get_dtype_size(op.dtype))
    if kind in (idaapi.o_imm, idaapi.o_near):
        return ('imm', int(op.value if kind == idaapi.o_imm else op.addr))
    if kind == idaapi.o_mem:
        return ('mem', None, int(op.addr), None, 1, ida_ua.get_dtype_size(op.dtype))
    if kind in (idaapi.o_displ, idaapi.o_phrase):
        base, index, scale = reg4(op), None, 1
        if int(op.specflag1):
            sib = int(op.specflag2)
            base = ida_idp.get_reg_name(sib & 7, 4)
            index_id = (sib >> 3) & 7
            if index_id != 4:
                index = ida_idp.get_reg_name(index_id, 4)
                scale = 1 << (sib >> 6)
        return ('mem', base, signed32(op.addr) if kind == idaapi.o_displ else 0, index, scale, ida_ua.get_dtype_size(op.dtype))
    return ('unknown',)

def flow_at(start, platform, call_purges=None, entry_state=None):
    function = ida_funcs.get_func(int(start))
    if function is None or function.start_ea != int(start) or idaapi.inf_is_64bit():
        raise ValueError('not an x86 function entry')
    blocks = []
    for block in ida_gdl.FlowChart(function):
        instructions = []
        for ea in idautils.Heads(block.start_ea, block.end_ea):
            insn = idautils.DecodeInstruction(ea)
            if insn is None:
                raise ValueError('undecodable instruction')
            mnemonic = (idc.print_insn_mnem(ea) or '').lower()
            operands = [decoded_operand(op) for op in insn.ops if int(op.type) != idaapi.o_void]
            item = dict(ea=int(ea), next_ea=int(ea)+int(insn.size), mnem=mnemonic, ops=operands,
                        sp=int(ida_frame.get_spd(function, ea)),
                        after=int(ida_frame.get_spd(function, ea+insn.size)),
                        writes=[flow_register(op) for i,op in enumerate(insn.ops)
                                if int(op.type)==idaapi.o_reg and changed_operand(insn,i)],
                        memory_writes=[decoded_operand(op) for i,op in enumerate(insn.ops)
                                       if int(op.type) in (idaapi.o_mem,idaapi.o_displ,idaapi.o_phrase) and changed_operand(insn,i)])
            if mnemonic == 'call' or mnemonic == 'jmp':
                if call_purges and ea in call_purges:
                    item['purge'] = call_purges[ea]
                item['direct'] = local_call_target(ea)
                target = item['direct']
                callee = ida_funcs.get_func(target) if target else None
                item['tail'] = mnemonic == 'jmp' and (int(insn.ops[0].type) != idaapi.o_near or
                                (callee is not None and callee.start_ea == target and target != function.start_ea))
                if mnemonic == 'call' and callee and callee.end_ea-callee.start_ea <= 8:
                    first = idautils.DecodeInstruction(target)
                    if first and idc.print_insn_mnem(target)=='mov' and int(first.ops[0].type)==idaapi.o_reg:
                        source = decoded_operand(first.ops[1])
                        if source == ('mem','esp',0,None,1,4) and idc.print_insn_mnem(target+first.size) in ('ret','retn'):
                            item['pc_reg'] = reg4(first.ops[0])
            if mnemonic in ('jz','jnz','je','jne'):
                item['branch'] = int(insn.ops[0].addr)
            instructions.append(item)
        blocks.append(dict(start=int(block.start_ea), succs=[int(s.start_ea) for s in block.succs()], insns=instructions))
    static_loads = {}
    for segment_start in idautils.Segments():
        if is_got(segment_start):
            segment = ida_segment.getseg(segment_start)
            static_loads.update({ea:int(ida_bytes.get_dword(ea)) for ea in range(segment.start_ea,segment.end_ea,4)})
    traced = trace_function(blocks, int(start), platform, static_loads, entry_state=entry_state)
    traced['blocks'] = {b['start']:b['succs'] for b in blocks}
    return traced

def callee_stack_purge(start):
    returns=set()
    for ea in idautils.FuncItems(start):
        if idc.print_insn_mnem(ea) not in ('ret','retn'):
            continue
        insn=idautils.DecodeInstruction(ea)
        returns.add(int(insn.ops[0].value) if int(insn.ops[0].type)==idaapi.o_imm else 0)
    if len(returns)!=1:
        raise ValueError('callee stack cleanup is ambiguous')
    purge=next(iter(returns))
    if purge%4 or not 0<=purge<=MAX_ARGUMENTS*4:
        raise ValueError('callee stack cleanup is unsupported')
    return purge

def reachable(graph, start):
    visited, pending = set(), [start]
    while pending:
        current = pending.pop()
        if current in visited:
            continue
        visited.add(current)
        pending.extend(graph.get(current, []))
    return visited

def call_map(flow):
    return {call['ea']:call for call in flow['calls']}

def direct_receiver(receiver, calls):
    if receiver is None or receiver[0] != 'result':
        return None
    return calls.get(receiver[1], {}).get('direct')

def one_slot(call):
    targets = virtual_targets(call['target'])
    offsets = {offset for _,offset in targets}
    return next(iter(offsets)) if len(offsets)==1 else None

def table_for(class_name):
    import ida_name
    mangled = {
        'CGameUI': ('_ZTV7CGameUI', '??_7CGameUI@@6B@', '.?AVCGameUI@@'),
        'VPanelWrapper': ('_ZTV13VPanelWrapper', '??_7VPanelWrapper@@6B@', '.?AVVPanelWrapper@@'),
        'vgui2::VPanel': ('_ZTVN5vgui26VPanelE', '??_7VPanel@vgui2@@6B@', '.?AVVPanel@vgui2@@'),
        'vgui2::Panel': ('_ZTVN5vgui25PanelE', '??_7Panel@vgui2@@6B@', '.?AVPanel@vgui2@@'),
    }
    elf_name, pe_name, descriptor_name = mangled[class_name]
    candidates = {}
    for name in (elf_name, pe_name):
        address = ida_name.get_name_ea(idaapi.BADADDR, name)
        if address != idaapi.BADADDR:
            candidates[int(address)+(8 if name.startswith('_ZTV') else 0)] = name
    strings = idautils.Strings(default_setup=False)
    strings.setup(strtypes=[ida_nalt.STRTYPE_C], minlen=4)
    for item in strings:
        if str(item) != descriptor_name:
            continue
        for ref in idautils.XrefsTo(int(item.ea)-8):
            locator = int(ref.frm)-12
            if ida_bytes.get_dword(locator)!=0 or ida_bytes.get_dword(locator+4)!=0:
                continue
            for pointer in idautils.XrefsTo(locator):
                address = int(pointer.frm)+4
                if is_code_address(int(ida_bytes.get_dword(address))):
                    candidates[address] = pe_name
    if len(candidates)!=1:
        raise ValueError('primary RTTI table is not unique: '+class_name)
    address, symbol = next(iter(candidates.items()))
    required_base = {
        'VPanelWrapper': (b'N5vgui26IPanelE',b'.?AVIPanel@vgui2@@'),
        'vgui2::Panel': (b'N5vgui212IClientPanelE',b'.?AVIClientPanel@vgui2@@'),
    }.get(class_name)
    if required_base is not None:
        bases = set()
        if symbol.startswith('_ZTV'):
            typeinfo = int(ida_bytes.get_dword(address-4))
            baseinfo = int(ida_bytes.get_dword(typeinfo+8))
            name_address = int(ida_bytes.get_dword(baseinfo+4))
            bases.add(idc.get_strlit_contents(name_address,-1,ida_nalt.STRTYPE_C))
            expected_base = required_base[0]
        else:
            locator = int(ida_bytes.get_dword(address-4))
            hierarchy = int(ida_bytes.get_dword(locator+16))
            count = int(ida_bytes.get_dword(hierarchy+8))
            array = int(ida_bytes.get_dword(hierarchy+12))
            if not 1 <= count <= 64:
                raise ValueError('invalid RTTI base class count')
            for index in range(count):
                descriptor = int(ida_bytes.get_dword(array+index*4))
                type_descriptor = int(ida_bytes.get_dword(descriptor))
                bases.add(idc.get_strlit_contents(type_descriptor+8,-1,ida_nalt.STRTYPE_C))
            expected_base = required_base[1]
        if expected_base not in bases:
            raise ValueError('RTTI interface base disagrees: '+class_name)
    entries = {}
    for index in range(512):
        target = int(ida_bytes.get_dword(address+index*4))
        if not is_code_address(target):
            break
        entries[index] = hex(target)
    if not entries:
        raise ValueError('empty primary RTTI table')
    return dict(vtable_class=class_name,vtable_symbol=symbol,vtable_va=hex(address),
                vtable_rva=hex(address-ida_nalt.get_imagebase()),vtable_size=hex(len(entries)*4),
                vtable_numvfunc=len(entries),vtable_entries=entries)
"""


async def walk(session, body, values):
    return await run_walk(session, FLOW_SOURCE + "\n" + IDA_FLOW + "\n" + body, values)


def artifact(directory, stem, platform):
    return _load_yaml_mapping(Path(directory) / f"{stem}.{platform}.yaml")


def function_address(directory, stem, platform):
    data = artifact(directory, stem, platform)
    return int(data["func_va"], 0) if data and data.get("func_va") else None


def write_slot(outputs, name, class_name, method, offset):
    output = _output_for_symbol(outputs, name)
    if output is None or not isinstance(offset, int) or offset < 0 or offset % 4:
        return False
    write_func_yaml(
        output,
        dict(
            func_name=f"{class_name}::{method}",
            vtable_name=class_name,
            vfunc_offset=hex(offset),
            vfunc_index=offset // 4,
        ),
    )
    return True


async def write_function(
    session, outputs, name, display_name, address, image_base, *, table=None, index=None, signature=True
):
    output = _output_for_symbol(outputs, name)
    if output is None:
        return False
    if signature:
        inspected = await _inspect_function_via_mcp(session, address, image_base, display_name)
        if not inspected:
            inspected = await _inspect_function_via_mcp(
                session, address, image_base, display_name, allow_across_function_boundary=True
            )
        if not inspected:
            # Inlined message-map initialization can share more than 256 bytes
            # with another constructor. Retain the normal relocation masking
            # and uniqueness validator while expanding only within this body.
            for byte_limit in (512, 1024, 2048, 4096):
                inspected = await _inspect_function_via_mcp(
                    session, address, image_base, display_name, signature_byte_limit=byte_limit
                )
                if inspected:
                    break
            if not inspected:
                return False
        payload = {key: inspected[key] for key in ("func_name", "func_va", "func_rva", "func_size", "func_sig")}
        if len(payload["func_sig"].split()) > int(payload["func_size"], 0):
            payload["func_sig_allow_across_function_boundary"] = True
    else:
        inspected = await walk(
            session,
            "f=ida_funcs.get_func(values['ea']); result={'size':int(f.end_ea-f.start_ea)} if f and f.start_ea==values['ea'] else {}",
            {"ea": address},
        )
        if not inspected.get("size"):
            return False
        payload = dict(
            func_name=display_name,
            func_va=hex(address),
            func_rva=hex(address - image_base),
            func_size=hex(inspected["size"]),
        )
    if table is not None:
        payload.update(vtable_name=table, vfunc_index=index, vfunc_offset=hex(index * 4))
    write_func_yaml(output, payload)
    return True
