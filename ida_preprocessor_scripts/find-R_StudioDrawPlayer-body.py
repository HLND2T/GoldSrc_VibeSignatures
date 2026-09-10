#!/usr/bin/env python3
"""Expose the existing player entry's body when GCC outlines its checked path.

Some ELF builds retain the player-index check in the public engine entry and
tail-jump into the rendering body. Follow only a unique external jump from a
function with no non-PC-thunk calls; never infer the body by address order or a byte pattern.
"""

from pathlib import Path
from ida_analyze_util import (
    _inspect_function_via_mcp,
    _load_yaml_mapping,
    _output_for_symbol,
    parse_mcp_result,
    write_func_yaml,
)

LOCATE = r"""
def main():
    import ida_funcs,ida_segment,ida_ua,idaapi,idautils,idc
    if idaapi.inf_is_64bit(): return {}
    def pc_thunk(callee):
        items=list(idautils.FuncItems(callee))
        if len(items)!=2: return False
        first=idautils.DecodeInstruction(items[0])
        return (first is not None and idc.print_insn_mnem(items[0]).lower()=='mov'
                and first.ops[0].type==ida_ua.o_reg
                and idc.print_operand(items[0],1).lower().replace(' ','') in ('[esp]','[esp+0]')
                and idc.print_insn_mnem(items[1]).lower() in ('ret','retn'))
    target=ENTRY
    seen=set()
    while target not in seen:
        seen.add(target)
        function=ida_funcs.get_func(target)
        segment=ida_segment.getseg(target)
        if not function or function.start_ea!=target or not segment or not segment.perm & ida_segment.SEGPERM_EXEC: return {}
        calls=False; jumps=set()
        for ea in idautils.FuncItems(target):
            mnemonic=idc.print_insn_mnem(ea).lower()
            if mnemonic=='call':
                insn=idautils.DecodeInstruction(ea)
                if insn.ops[0].type!=ida_ua.o_near or not pc_thunk(int(insn.ops[0].addr)): calls=True
            if mnemonic=='jmp':
                insn=idautils.DecodeInstruction(ea)
                if insn.ops[0].type!=ida_ua.o_near: calls=True; continue
                destination=int(insn.ops[0].addr)
                owner=ida_funcs.get_func(destination)
                if owner and owner.start_ea!=target and owner.start_ea==destination: jumps.add(destination)
        if calls or len(jumps)!=1:
            return {'pointer_size':4,'target':target}
        target=jumps.pop()
    return {}
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
    entry = _load_yaml_mapping(Path(new_binary_dir) / f"R_StudioDrawPlayer.{platform}.yaml")
    if not entry:
        return False
    located = parse_mcp_result(
        await session.call_tool("py_eval", {"code": LOCATE.replace("ENTRY", str(int(entry["func_va"], 0)))})
    )
    if not isinstance(located, dict) or located.get("pointer_size") != 4:
        return False
    name = "R_StudioDrawPlayerBody"
    output = _output_for_symbol(expected_outputs, name)
    function = await _inspect_function_via_mcp(session, located["target"], image_base, name)
    across = function is None
    if across:
        function = await _inspect_function_via_mcp(
            session, located["target"], image_base, name, allow_across_function_boundary=True
        )
    if not output or not function:
        return False
    payload = {key: function[key] for key in ("func_name", "func_va", "func_rva", "func_size", "func_sig")}
    if across:
        payload["func_sig_allow_across_function_boundary"] = True
    write_func_yaml(output, payload)
    return True
