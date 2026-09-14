"""Deliver portal layout traces to the IDA worker without large MCP responses."""

import inspect
import json

from ida_analyze_util import parse_mcp_result
import ida_preprocessor_scripts._portal_layout as layout

DECODER = r"""
import ida_funcs, ida_ua, ida_idp, ida_nalt, ida_frame, idaapi, idautils, idc, re
def decode_function(ea):
    if idaapi.inf_is_64bit():
        raise ValueError('portal layout requires x86-32')
    f = ida_funcs.get_func(ea)
    if not f or f.start_ea != ea:
        raise ValueError('layout predecessor is not a function start')
    imports = {}
    def imported(address, name, ordinal):
        if name:
            imports[int(address)] = name.lstrip('_').split('@')[0]
        return True
    for i in range(ida_nalt.get_import_module_qty()):
        ida_nalt.enum_import_names(i, imported)
    result = []
    for address in idautils.FuncItems(ea):
        # Ignore detached EH cleanup chunks; their entry state is different.
        if not f.start_ea <= address < f.end_ea:
            continue
        insn = idautils.DecodeInstruction(address)
        if insn is None:
            raise ValueError('instruction decode failed')
        ops, writes, memory_writes = [], [], []
        for i, op in enumerate(insn.ops):
            if op.type == ida_ua.o_void:
                break
            text = (idc.print_operand(address, i) or '').lower()
            item = {'kind': 'unsupported', 'size': ida_ua.get_dtype_size(op.dtype)}
            if op.type == ida_ua.o_reg:
                item.update(kind='reg', reg=text)
                if insn.get_canon_feature() & getattr(ida_idp, 'CF_CHG%d' % (i+1)):
                    root = {'al':'eax','ah':'eax','ax':'eax','bl':'ebx','bh':'ebx','bx':'ebx',
                            'cl':'ecx','ch':'ecx','cx':'ecx','dl':'edx','dh':'edx','dx':'edx',
                            'si':'esi','di':'edi','bp':'ebp','sp':'esp'}.get(text,text)
                    writes.append(root)
            elif op.type == ida_ua.o_imm:
                item.update(kind='imm',value=int(op.value))
            elif op.type == ida_ua.o_near:
                target = int(op.addr)
                name = (idc.get_func_name(target) or '').lstrip('._').split('@')[0]
                if (idc.get_segm_name(target) or '').startswith('.plt') and name in imports.values():
                    item.update(kind='api',size=4,name=name)
                else:
                    item.update(kind='func',size=4,value=target)
            elif op.type == ida_ua.o_mem and int(op.addr) in imports:
                item.update(kind='api',name=imports[int(op.addr)])
            elif op.type in (ida_ua.o_phrase, ida_ua.o_displ) and 'fs:' not in text and 'gs:' not in text:
                regs = re.findall(r'\be(?:ax|bx|cx|dx|si|di|bp|sp)\b',text)
                if len(regs) == 1 and '*' not in text:
                    disp = int(op.addr) & 0xffffffff if op.type == ida_ua.o_displ else 0
                    if disp & 0x80000000:
                        disp -= 0x100000000
                    item.update(kind='mem',base=regs[0],disp=disp)
            ops.append(item)
            if item['kind'] == 'mem' and insn.get_canon_feature() & getattr(ida_idp, 'CF_CHG%d' % (i+1)):
                memory_writes.append(item)
        result.append({'ea':int(address),'mnemonic':(idc.print_insn_mnem(address) or '').lower(),
                       'operands':ops,'writes':writes,'memory_writes':memory_writes,'stack_delta':ida_frame.get_sp_delta(f,address+insn.size)})
    indices = {item['ea']: i for i, item in enumerate(result)}
    for item in result:
        item['successors'] = [indices[int(target)] for target in idautils.CodeRefsFrom(item['ea'], 1) if int(target) in indices]
        if item['mnemonic']=='call' and item['operands'] and item['operands'][0]['kind']=='func':
            target = item['operands'][0]['value']
            thunk = idautils.DecodeInstruction(target)
            if thunk and (idc.print_insn_mnem(target) or '').lower()=='mov' and thunk.ops[0].type==ida_ua.o_reg and thunk.ops[1].type in (ida_ua.o_phrase,ida_ua.o_displ):
                operand = (idc.print_operand(target,1) or '').lower()
                registers = re.findall(r'\be(?:ax|bx|cx|dx|si|di|bp|sp)\b',operand)
                if registers==['esp'] and '*' not in operand and int(thunk.ops[1].addr)==0 and (idc.print_insn_mnem(target+thunk.size) or '').lower() in ('ret','retn'):
                    item['call_writes']=[(idc.print_operand(target,0) or '').lower()]
    return result
def callees(ea):
    return {op['value'] for insn in decode_function(ea) if insn['mnemonic']=='call'
            for op in insn['operands'] if op['kind']=='func' and ida_funcs.get_func(op['value'])
            and ida_funcs.get_func(op['value']).start_ea == op['value']}
"""


async def run_layout_walk(session, values, body):
    source = inspect.getsource(layout) + "\n" + DECODER + "\n" + body
    wrapper = (
        'def main():\n import traceback,json\n ns={"values":' + repr(values) + "}\n"
        " try:\n  exec(" + json.dumps(source) + ',ns)\n  return json.dumps(ns["result"])\n'
        ' except Exception:\n  return {"error":traceback.format_exc()[-1500:]}\nmain()'
    )
    result = parse_mcp_result(await session.call_tool("py_eval", {"code": wrapper}))
    if not isinstance(result, dict) or result.get("error"):
        raise ValueError(f"portal layout trace failed: {result}")
    return result
