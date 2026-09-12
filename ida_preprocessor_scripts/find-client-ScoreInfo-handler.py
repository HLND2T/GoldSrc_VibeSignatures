#!/usr/bin/env python3
"""Resolve ScoreInfo registration, its interface object, and its concrete handler.

CS assigns gCSViewPortMsgs to a secondary subobject of its static viewport.
CZDS assigns gViewPortMsgs in the viewport constructor. Match the explicit
pointer/vptr stores for that same subobject; neither interface slot nor object
layout is copied across builds. Public registration and current constructor
dataflow establish the handler before its private globals are recovered.
"""

from ida_analyze_util import _inspect_function_via_mcp, _output_for_symbol, parse_mcp_result, write_func_yaml
from ida_preprocessor_scripts._client_registration_common import REGISTRATION_QUERY

LOCATE = (
    REGISTRATION_QUERY
    + r"""
def main(registered_callbacks):
    import ida_bytes,ida_funcs,ida_gdl,ida_nalt,ida_segment,ida_ua,idaapi,idautils,idc
    if idaapi.inf_is_64bit(): return {}
    def data(value):
        segment=ida_segment.getseg(value) if 0<=value<=0xffffffff else None
        return segment is not None and not (segment.perm & ida_segment.SEGPERM_EXEC)
    def function(value):
        segment=ida_segment.getseg(value) if 0<=value<=0xffffffff else None
        if segment is None or not (segment.perm & ida_segment.SEGPERM_EXEC): return False
        owner=ida_funcs.get_func(value)
        if owner is None:
            flags=ida_bytes.get_full_flags(value)
            if ida_bytes.is_code(flags) or ida_bytes.is_unknown(flags): ida_funcs.add_func(value)
            owner=ida_funcs.get_func(value)
        return owner is not None and owner.start_ea==value
    callbacks=registered_callbacks('ScoreInfo')
    if len(callbacks)!=1: return {'error':'ScoreInfo callback is not unique','callbacks':list(callbacks)}
    callback=callbacks.pop()
    registers={}; dispatches=set()
    for ea in idautils.FuncItems(callback):
        insn=idautils.DecodeInstruction(ea)
        if not insn: continue
        mnemonic=idc.print_insn_mnem(ea).lower()
        dest,source=insn.ops[0],insn.ops[1]
        if mnemonic in ('call','jmp') and dest.type in (ida_ua.o_displ,ida_ua.o_phrase):
            value=registers.get(dest.phrase)
            offset=int(dest.addr) if dest.type==ida_ua.o_displ else 0
            if value and value[0]=='vtable' and offset>=0 and offset%4==0:
                dispatches.add((value[1],offset))
        if mnemonic=='mov' and dest.type==ida_ua.o_reg:
            value=None
            if source.type==ida_ua.o_mem and data(int(source.addr)):
                value=('object',int(source.addr))
            elif source.type==ida_ua.o_reg:
                value=registers.get(source.reg)
            elif source.type in (ida_ua.o_phrase,ida_ua.o_displ) and int(source.addr)==0:
                base=registers.get(source.phrase)
                if base and base[0]=='object': value=('vtable',base[1])
            registers.pop(dest.reg,None)
            if value: registers[dest.reg]=value
    if len(dispatches)!=1: return {'error':'ScoreInfo interface dispatch is not unique','dispatches':list(dispatches)}
    pointer,slot=dispatches.pop()
    writers=set()
    for ea in idautils.DataRefsTo(pointer):
        insn=idautils.DecodeInstruction(ea)
        owner=ida_funcs.get_func(ea)
        if owner and insn and idc.print_insn_mnem(ea).lower()=='mov' and insn.ops[0].type==ida_ua.o_mem and int(insn.ops[0].addr)==pointer:
            writers.add(owner.start_ea)
    tables=set()
    def plus(expr,offset):
        if expr is None: return None
        return (expr[0],(expr[1]+offset)&0xffffffff) if expr[0]=='constant' else (expr[0],expr[1],expr[2]+offset)
    max_constructor_instructions=8192
    for writer in writers:
        pending=[(writer,{reg:('register',reg,0) for reg in range(8)},{},set())]
        instruction_budget=max_constructor_instructions
        def address(op):
            if op.type==ida_ua.o_mem: return ('constant',int(op.addr))
            if op.type in (ida_ua.o_phrase,ida_ua.o_displ) and not op.specflag1:
                offset=int(op.addr) if op.type==ida_ua.o_displ else 0
                if offset & 0x80000000: offset-=0x100000000
                return plus(registers.get(op.phrase),offset)
            return None
        while pending:
            cursor,registers,memory,seen=pending.pop()
            while True:
                instruction_budget-=1
                if instruction_budget<0 or cursor in seen:
                    return {'error':'ScoreInfo constructor control flow is cyclic or exceeds its bound'}
                seen.add(cursor)
                insn=idautils.DecodeInstruction(cursor)
                if not insn: break
                mnemonic=idc.print_insn_mnem(cursor).lower()
                dest,source=insn.ops[0],insn.ops[1]
                if mnemonic.startswith('ret'): break
                if mnemonic.startswith('j'):
                    if dest.type!=ida_ua.o_near:
                        return {'error':'ScoreInfo constructor has an unresolved branch'}
                    if mnemonic=='jmp':
                        cursor=int(dest.addr); continue
                    # Null-guarded subobject conversions still carry the same
                    # vptr evidence on the non-null path. Keep branch states
                    # separate and require one concrete handler across them.
                    pending.append((int(dest.addr),dict(registers),dict(memory),set(seen)))
                    cursor+=insn.size
                    continue
                if mnemonic.startswith('loop'):
                    return {'error':'ScoreInfo constructor has unsupported loop control flow'}
                if mnemonic=='call':
                    for reg in (0,1,2): registers.pop(reg,None)
                    memory={}
                elif mnemonic in ('mov','lea'):
                    value=None
                    if mnemonic=='lea':
                        refs={int(x) for x in idautils.DataRefsFrom(cursor) if 0<=x<=0xffffffff and data(x)}
                        value=('constant',refs.pop()) if len(refs)==1 else address(source)
                    elif source.type==ida_ua.o_imm: value=('constant',int(source.value))
                    elif source.type==ida_ua.o_reg: value=registers.get(source.reg)
                    else:
                        source_address=address(source)
                        value=memory.get(source_address)
                        # A cdecl constructor receives this through its stack argument.
                        # Preserve that symbolic object across the base constructor call
                        # when it is kept in a callee-saved register.
                        if value is None and source.type in (ida_ua.o_phrase,ida_ua.o_displ) and '[esp' in idc.print_operand(cursor,1).lower():
                            value=('stack_value',cursor,0)
                    if dest.type==ida_ua.o_reg:
                        registers.pop(dest.reg,None)
                        if value is not None: registers[dest.reg]=value
                    else:
                        destination=address(dest)
                        if destination is not None:
                            memory[destination]=value
                            if destination==('constant',pointer) and value!=('constant',0):
                                table=memory.get(value)
                                if not table or table[0]!='constant' or not data(table[1]):
                                    return {'error':'ScoreInfo constructor has an unproven non-null interface assignment'}
                                tables.add(table[1])
                elif mnemonic=='xor' and dest.type==ida_ua.o_reg and source.type==ida_ua.o_reg and dest.reg==source.reg:
                    registers[dest.reg]=('constant',0)
                elif mnemonic in ('add','sub') and dest.type==ida_ua.o_reg and source.type==ida_ua.o_imm:
                    value=plus(registers.get(dest.reg),int(source.value)*(1 if mnemonic=='add' else -1))
                    registers.pop(dest.reg,None)
                    if value is not None: registers[dest.reg]=value
                elif dest.type==ida_ua.o_reg and mnemonic not in ('push','cmp','test'):
                    registers.pop(dest.reg,None)
                cursor+=insn.size
    targets=set()
    for table in tables:
        target=ida_bytes.get_dword(table+slot)
        if not function(target): continue
        # Secondary-interface vtables can contain a this-adjusting jump thunk.
        items=list(idautils.FuncItems(target))
        if 1<=len(items)<=3:
            last=idautils.DecodeInstruction(items[-1])
            prior=[idautils.DecodeInstruction(ea) for ea in items[:-1]]
            adjusts=all(idc.print_insn_mnem(ea) in ('add','sub') and insn.ops[1].type==ida_ua.o_imm
                        and (idc.print_operand(ea,0)=='ecx' or ('[esp' in idc.print_operand(ea,0) and insn.ops[0].addr==4))
                        for ea,insn in zip(items[:-1],prior))
            if adjusts and idc.print_insn_mnem(items[-1])=='jmp' and last.ops[0].type==ida_ua.o_near and function(last.ops[0].addr):
                target=int(last.ops[0].addr)
        targets.add(int(target))
    if len(targets)!=1: return {'error':'ScoreInfo concrete handler is not unique','pointer':hex(pointer),'slot':slot,'tables':[hex(x) for x in tables],'targets':[hex(x) for x in targets]}
    return {'pointer_size':4,'target':targets.pop(),'callback':callback,'interface_pointer':pointer,'slot':slot,'tables':list(tables)}
import json
result=json.dumps(main(registered_callbacks))
"""
)


async def preprocess_skill(
    session,
    skill_name,
    expected_outputs,
    old_yaml_map,
    new_binary_dir,
    platform,
    image_base,
    debug=False,
):
    _ = skill_name, old_yaml_map, new_binary_dir, platform
    located = parse_mcp_result(await session.call_tool("py_eval", {"code": LOCATE}))
    if not isinstance(located, dict) or located.get("pointer_size") != 4:
        if debug:
            print("ScoreInfo locator:", located)
        return False
    name = "ClientScoreInfoHandler"
    output = _output_for_symbol(expected_outputs, name)
    function = await _inspect_function_via_mcp(session, located["target"], image_base, name)
    across = function is None
    if across:
        function = await _inspect_function_via_mcp(
            session,
            located["target"],
            image_base,
            name,
            allow_across_function_boundary=True,
        )
    if not function or not output:
        return False
    payload = {key: function[key] for key in ("func_name", "func_va", "func_rva", "func_size", "func_sig")}
    if across:
        payload["func_sig_allow_across_function_boundary"] = True
    write_func_yaml(output, payload)
    return True
