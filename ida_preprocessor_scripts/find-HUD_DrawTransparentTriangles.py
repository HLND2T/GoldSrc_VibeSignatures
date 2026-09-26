#!/usr/bin/env python3
"""Locate the Sven client callback through its public PE/ELF export.

Use the ABI name, not an IDB label or the engine's ClientDLL wrapper. Both
svencoop-8948 and svencoop-10257 export one standalone entry on each platform.
"""

from ida_analyze_util import _inspect_function_via_mcp, _output_for_symbol, parse_mcp_result, write_func_yaml

TARGET = "HUD_DrawTransparentTriangles"
LOCATE_EXPORT = r"""
import ida_funcs, idaapi, idautils, json
entries = [int(ea) for _, _, ea, name in idautils.Entries()
           if name == "HUD_DrawTransparentTriangles"]
valid = len(entries) == 1
if valid:
    function = ida_funcs.get_func(entries[0])
    valid = function is not None and int(function.start_ea) == entries[0]
result = json.dumps({"pointer_size": 8 if idaapi.inf_is_64bit() else 4,
                     "entry": entries[0] if valid else None})
"""


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
    _ = skill_name, old_yaml_map, new_binary_dir
    if platform not in {"windows", "linux"}:
        return False
    output = _output_for_symbol(expected_outputs, TARGET)
    if output is None:
        return False
    located = parse_mcp_result(await session.call_tool("py_eval", {"code": LOCATE_EXPORT}))
    if not isinstance(located, dict) or located.get("pointer_size") != 4 or located.get("entry") is None:
        if debug:
            print(f"  {TARGET}: expected exactly one exported x86 function entry: {located}")
        return False
    function = await _inspect_function_via_mcp(session, located["entry"], image_base, TARGET)
    if not function:
        return False
    write_func_yaml(
        output, {key: function[key] for key in ("func_name", "func_va", "func_rva", "func_size", "func_sig")}
    )
    return True
