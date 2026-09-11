#!/usr/bin/env python3
"""Recover Sven ELF's public engine table at Initialize(&cl_enginefuncs, 7).

This direct global locator follows the two cdecl argument definitions in the
verified ClientDLL_Init block. Unlike a source-order guess, the version and
table argument reach the same indirect call; table entries must be code.
The Windows/absolute form already lives in find-ClientDLL_HudInit-decompiles.
"""

from pathlib import Path
from ida_analyze_util import (
    _inspect_function_via_mcp,
    _load_yaml_mapping,
    _output_for_symbol,
    gv_resolution_fields_via_mcp,
    parse_mcp_result,
    write_gv_yaml,
)

LOCATE = r"""
def main():
    import ida_bytes, ida_funcs, ida_gdl, ida_segment, ida_ua, idaapi, idautils, idc
    owner=ida_funcs.get_func(OWNER_EA)
    if idaapi.inf_is_64bit() or owner is None or owner.start_ea != OWNER_EA:
        return {}
    candidates=[]
    def data(ea):
        seg=ida_segment.getseg(ea)
        return seg is not None and not (seg.perm & ida_segment.SEGPERM_EXEC)
    def table(ea):
        if not data(ea) or ea % 4:
            return False
        # SDK's initial twelve entries are function pointers on all x86 peers.
        for index in range(12):
            target=ida_bytes.get_dword(ea+index*4)
            seg=ida_segment.getseg(target)
            if seg is None or not (seg.perm & ida_segment.SEGPERM_EXEC):
                return False
        return True
    for block in ida_gdl.FlowChart(owner):
        registers={}
        stack={}
        for ea in idautils.Heads(block.start_ea,block.end_ea):
            insn=idautils.DecodeInstruction(ea)
            if not insn: break
            mnemonic=idc.print_insn_mnem(ea).lower()
            dest,source=insn.ops[0],insn.ops[1]
            if mnemonic=='call':
                if dest.type in (ida_ua.o_displ,ida_ua.o_mem):
                    version=stack.get(4)
                    argument=stack.get(0)
                    if version and version[0]==7 and argument and table(argument[0]):
                        candidates.append(argument)
                registers={}
                stack={}
                continue
            if mnemonic not in ('mov','lea'):
                if dest.type==ida_ua.o_reg and mnemonic not in ('push','cmp','test'):
                    registers.pop(dest.reg,None)
                continue
            value=None
            if mnemonic=='mov' and source.type==ida_ua.o_imm:
                value=(int(source.value),int(ea),int(source.offb),insn.size)
            elif mnemonic=='mov' and source.type==ida_ua.o_reg:
                value=registers.get(source.reg)
            elif mnemonic=='lea':
                refs={int(x) for x in idautils.DataRefsFrom(ea) if 0<=x<=0xffffffff and data(x)}
                if len(refs)==1 and source.offb and source.offb+4<=insn.size:
                    value=(refs.pop(),int(ea),int(source.offb),insn.size)
            if dest.type==ida_ua.o_reg:
                registers.pop(dest.reg,None)
                if value: registers[dest.reg]=value
            elif dest.type in (ida_ua.o_displ,ida_ua.o_phrase) and '[esp' in idc.print_operand(ea,0).lower():
                offset=int(dest.addr) if dest.type==ida_ua.o_displ else 0
                stack.pop(offset,None)
                if value: stack[offset]=value
    unique=set(candidates)
    return {'access':list(unique.pop())} if len(unique)==1 else {}
import json
result=json.dumps(main())
"""


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
    _ = skill_name, old_yaml_map, debug
    if platform != "linux":
        return False
    owner = _load_yaml_mapping(Path(new_binary_dir) / f"ClientDLL_Init.{platform}.yaml")
    if not owner:
        return False
    located = parse_mcp_result(
        await session.call_tool("py_eval", {"code": LOCATE.replace("OWNER_EA", str(int(owner["func_va"], 0)))})
    )
    if not isinstance(located, dict) or "access" not in located:
        return False
    address, ea, disp, size = located["access"]
    function = await _inspect_function_via_mcp(
        session, int(owner["func_va"], 0), image_base, "ClientDLL_Init", allow_across_function_boundary=True
    )
    metadata = await gv_resolution_fields_via_mcp(session, ea, disp, address, image_base, platform)
    output = _output_for_symbol(expected_outputs, "cl_enginefuncs")
    if not function or metadata is None or not output:
        return False
    write_gv_yaml(
        output,
        {
            "gv_name": "cl_enginefuncs",
            "gv_va": hex(address),
            "gv_rva": hex(address - image_base),
            "gv_sig": function["func_sig"],
            "gv_sig_va": function["func_va"],
            "gv_inst_offset": ea - int(owner["func_va"], 0),
            "gv_inst_length": size,
            "gv_inst_disp": disp,
            "gv_sig_allow_across_function_boundary": True,
            **metadata,
        },
    )
    return True
