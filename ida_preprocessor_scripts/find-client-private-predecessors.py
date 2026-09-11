#!/usr/bin/env python3
"""Materialize public client entries used as private-symbol predecessors.

Exports are ABI roots, not guesses based on IDB names. Only exact export-table
entries are accepted, and each generated signature is validated in this IDB.
"""

from ida_analyze_util import (
    _inspect_function_via_mcp,
    _output_for_symbol,
    parse_mcp_result,
    write_func_yaml,
)

TARGET_FUNCTION_NAMES = ["HUD_GetStudioModelInterface", "CL_IsThirdPerson", "V_CalcRefdef"]
LOCATE_EXPORTS = r"""
import ida_funcs, idaapi, idautils, json
targets = ["HUD_GetStudioModelInterface", "CL_IsThirdPerson", "V_CalcRefdef"]
entries = {name: [] for name in targets}
for index, ordinal, ea, name in idautils.Entries():
    if name in entries:
        func = ida_funcs.get_func(ea)
        if func and func.start_ea == ea:
            entries[name].append(int(ea))
result = json.dumps({"pointer_size": 8 if idaapi.inf_is_64bit() else 4, "entries": entries})
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
    _ = skill_name, old_yaml_map, new_binary_dir
    if platform not in {"windows", "linux"}:
        return False
    located = parse_mcp_result(await session.call_tool("py_eval", {"code": LOCATE_EXPORTS}))
    if not isinstance(located, dict) or located.get("pointer_size") != 4:
        return False
    outputs = {}
    for name in TARGET_FUNCTION_NAMES:
        output = _output_for_symbol(expected_outputs, name)
        if output is None:
            continue
        candidates = located.get("entries", {}).get(name, [])
        if not isinstance(candidates, list) or len(set(candidates)) != 1:
            if debug:
                print(f"  {name}: expected one exported function start, got {candidates}")
            return False
        function = await _inspect_function_via_mcp(session, candidates[0], image_base, name)
        if not function or not function.get("func_sig"):
            return False
        outputs[output] = {key: function[key] for key in ("func_name", "func_va", "func_rva", "func_size", "func_sig")}
    for output, payload in outputs.items():
        write_func_yaml(output, payload)
    return bool(outputs)
