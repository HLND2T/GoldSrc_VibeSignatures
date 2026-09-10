#!/usr/bin/env python3
"""Find Sven's pitch-drift entry from pfnAddCommand("centerview", callback).

Source: cl_dll/view.cpp V_Init and V_StartPitchDrift. Read the current cdecl
registration arguments; no source address or instruction pattern is a locator.
"""

from ida_preprocessor_scripts._client_registration_common import REGISTRATION_QUERY
from ida_analyze_util import _inspect_function_via_mcp, _output_for_symbol, parse_mcp_result, write_func_yaml

LOCATE = (
    REGISTRATION_QUERY
    + r"""
import idaapi,json
result=json.dumps({'pointer_size':4,'targets':list(registered_callbacks('centerview'))} if not idaapi.inf_is_64bit() else {})
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
    if not isinstance(located, dict) or located.get("pointer_size") != 4 or len(located.get("targets", [])) != 1:
        if debug:
            print("Pitch-drift registration:", located)
        return False
    name = "V_StartPitchDrift"
    output = _output_for_symbol(expected_outputs, name)
    function = await _inspect_function_via_mcp(session, located["targets"][0], image_base, name)
    across = function is None
    if across:
        function = await _inspect_function_via_mcp(
            session, located["targets"][0], image_base, name, allow_across_function_boundary=True
        )
    if not function or not output:
        return False
    payload = {key: function[key] for key in ("func_name", "func_va", "func_rva", "func_size", "func_sig")}
    if across:
        payload["func_sig_allow_across_function_boundary"] = True
    write_func_yaml(output, payload)
    return True
