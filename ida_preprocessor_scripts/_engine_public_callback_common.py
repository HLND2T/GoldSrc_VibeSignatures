#!/usr/bin/env python3
"""Resolve current public engine callbacks, including forwarding API shims."""

from pathlib import Path

from ida_analyze_util import (
    _inspect_function_via_mcp,
    _load_yaml_mapping,
    _output_for_symbol,
    parse_mcp_result,
    write_func_yaml,
)


async def preprocess_engine_callback(
    session,
    expected_outputs,
    new_binary_dir,
    platform,
    image_base,
    *,
    name,
    slot,
    indirect_table_offset=None,
):
    table = _load_yaml_mapping(Path(new_binary_dir) / f"cl_enginefuncs.{platform}.yaml")
    if not table:
        return False
    table_ea = int(table["gv_va"], 0)
    code = f"""
import ida_bytes, ida_funcs, ida_segment, ida_ua, idaapi, idautils, idc, json
table_ea = {table_ea}
indirect_table_offset = {indirect_table_offset!r}
slot = {int(slot)}
if indirect_table_offset is None:
    callback_table = table_ea
else:
    callback_table = ida_bytes.get_dword(table_ea + int(indirect_table_offset))
entry = int(callback_table or 0) + slot * 4
target = ida_bytes.get_dword(entry)
def unwrap(start):
    items=list(idautils.FuncItems(start))
    if not items or len(items)>16:
        return start
    calls=[]
    for ea in items:
        insn=idautils.DecodeInstruction(ea)
        mnemonic=idc.print_insn_mnem(ea).lower()
        if mnemonic=='jmp' and len(items)==1 and insn.ops[0].type==ida_ua.o_near:
            return int(insn.ops[0].addr)
        if mnemonic=='call':
            if insn.ops[0].type!=ida_ua.o_near: return start
            callee=int(insn.ops[0].addr)
            body=list(idautils.FuncItems(callee))
            pc_thunk=(len(body)==2 and idc.print_insn_mnem(body[0])=='mov' and idc.print_operand(body[0],1) in ('[esp]','[esp+0]') and idc.print_insn_mnem(body[1])=='retn')
            if not pc_thunk: calls.append(callee)
        elif mnemonic not in ('mov','push','pop','sub','add','retn','ret','nop'):
            return start
        elif mnemonic=='mov' and insn.ops[0].type!=ida_ua.o_reg:
            operand=idc.print_operand(ea,0).lower()
            if '[esp' not in operand and '[ebp' not in operand: return start
    return calls[0] if len(calls)==1 else start
# SvEngine inserts a forwarding API shim. Follow only a side-effect-free
# straight-line wrapper with one non-PC-thunk callee, never a nearby function.
seen=set()
cycle=False
while target not in seen:
    seen.add(target)
    next_target=unwrap(target)
    if next_target==target: break
    target=next_target
else:
    cycle=True
table_segment = ida_segment.getseg(callback_table)
entry_segment = ida_segment.getseg(entry)
segment = ida_segment.getseg(target)
function = ida_funcs.get_func(target)
valid = (not cycle and not idaapi.inf_is_64bit()
         and table_segment is not None and entry_segment is not None
         and not (table_segment.perm & ida_segment.SEGPERM_EXEC)
         and not (entry_segment.perm & ida_segment.SEGPERM_EXEC)
         and segment is not None
         and segment.perm & ida_segment.SEGPERM_EXEC
         and function is not None and function.start_ea == target)
result = json.dumps({{'target': int(target), 'callback_table': int(callback_table),
                      'entry': int(entry)}} if valid else {{}})
"""
    located = parse_mcp_result(await session.call_tool("py_eval", {"code": code}))
    if not isinstance(located, dict) or "target" not in located:
        return False
    output = _output_for_symbol(expected_outputs, name)
    function = await _inspect_function_via_mcp(session, located["target"], image_base, name)
    allow_across = function is None
    if allow_across:
        function = await _inspect_function_via_mcp(
            session,
            located["target"],
            image_base,
            name,
            allow_across_function_boundary=True,
        )
    if not output or not function:
        return False
    payload = {key: function[key] for key in ("func_name", "func_va", "func_rva", "func_size", "func_sig")}
    if allow_across:
        payload["func_sig_allow_across_function_boundary"] = True
    write_func_yaml(output, payload)
    return True
