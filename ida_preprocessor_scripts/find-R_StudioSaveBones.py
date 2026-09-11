#!/usr/bin/env python3
"""Locate the independent writer of the bone count/name cache.

R_StudioSaveBones copies each bone name and both transformation matrices.
MergeBones reads the same cache; compilers can inline the writer into the
top-level DrawModel/DrawPlayer routines. Exclude those proven source roles,
including body aliases and their bone-setup/attachment calls, then require
one remaining function referencing both cached_numbones and cached_bonename.
"""

import json
from pathlib import Path

from ida_analyze_util import (
    _inspect_function_via_mcp,
    _load_yaml_mapping,
    _output_for_symbol,
    parse_mcp_result,
    write_func_yaml,
)

LOCATE = r"""
def main(values):
    import ida_funcs,ida_segment,idaapi,idautils
    if idaapi.inf_is_64bit(): return {}
    def owners(address):
        return {ida_funcs.get_func(x).start_ea for x in idautils.DataRefsTo(address) if ida_funcs.get_func(x)}
    count,name=values['globals']
    for address in (count,name):
        segment=ida_segment.getseg(address)
        if not segment or segment.perm & ida_segment.SEGPERM_EXEC: return {}
    # Source declares 32-byte names. Optimized SaveBones can start its pointer
    # at name[0][31] for the trailing NUL and address the string as pointer-31.
    # Match a current xref into the first name entry, not just its base label.
    name_owners=set()
    for offset in range(32): name_owners.update(owners(name+offset))
    candidates=owners(count)&name_owners
    candidates.difference_update(values['exclude'])
    for callee in values['callees']:
        for source in idautils.CodeRefsTo(callee,False):
            function=ida_funcs.get_func(source)
            if function: candidates.discard(function.start_ea)
    return {'pointer_size':4,'targets':list(candidates)}
import json
result=json.dumps(main(VALUES))
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
    _ = skill_name, old_yaml_map
    values = {}
    for key, field, names in (
        ("globals", "gv_va", ["cached_numbones", "cached_bonename"]),
        (
            "exclude",
            "func_va",
            ["R_StudioMergeBones", "R_StudioDrawModel", "R_StudioDrawPlayer", "R_StudioDrawPlayerBody"],
        ),
        ("callees", "func_va", ["R_StudioSetupBones", "R_StudioCalcAttachments"]),
    ):
        values[key] = []
        for name in names:
            artifact = _load_yaml_mapping(Path(new_binary_dir) / f"{name}.{platform}.yaml")
            if not artifact or field not in artifact:
                return False
            values[key].append(int(artifact[field], 0))
    located = parse_mcp_result(
        await session.call_tool("py_eval", {"code": LOCATE.replace("VALUES", json.dumps(values))})
    )
    if not isinstance(located, dict) or located.get("pointer_size") != 4 or len(located.get("targets", [])) != 1:
        if debug:
            print("Bone-cache writer candidates:", located)
        return False
    name = "R_StudioSaveBones"
    output = _output_for_symbol(expected_outputs, name)
    function = await _inspect_function_via_mcp(session, located["targets"][0], image_base, name)
    across = function is None
    if across:
        function = await _inspect_function_via_mcp(
            session, located["targets"][0], image_base, name, allow_across_function_boundary=True
        )
    if not output or not function:
        return False
    payload = {key: function[key] for key in ("func_name", "func_va", "func_rva", "func_size", "func_sig")}
    if across:
        payload["func_sig_allow_across_function_boundary"] = True
    write_func_yaml(output, payload)
    return True
