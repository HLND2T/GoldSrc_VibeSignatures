#!/usr/bin/env python3
"""Read the named SVC handler from the validated current client parse table."""

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
    import ida_bytes, ida_funcs, ida_nalt, ida_segment, idaapi
    if idaapi.inf_is_64bit():
        return {}
    entry_size = 12  # svc_func_t: opcode, pszname, pfnParse, all x86 dwords.
    matches = []
    for index in range(80):
        entry = TABLE_EA + index * entry_size
        opcode = ida_bytes.get_dword(entry)
        name = ida_bytes.get_strlit_contents(ida_bytes.get_dword(entry + 4), -1, ida_nalt.STRTYPE_C)
        if opcode & 0xff == 0xff:
            break
        if opcode != index:
            return {}
        if name == SERVICE_NAME:
            target = ida_bytes.get_dword(entry + 8)
            segment = ida_segment.getseg(target)
            function = ida_funcs.get_func(target)
            # Older blob builds leave indirect-only service handlers unowned.
            # The validated named table entry is explicit code-entry evidence.
            if segment and segment.perm & ida_segment.SEGPERM_EXEC and function is None:
                flags = ida_bytes.get_full_flags(target)
                if ida_bytes.is_code(flags) or ida_bytes.is_unknown(flags):
                    ida_funcs.add_func(target)
                    function = ida_funcs.get_func(target)
            if segment and segment.perm & ida_segment.SEGPERM_EXEC and function and function.start_ea == target:
                matches.append(int(target))
    return {'pointer_size': 4, 'targets': matches}
import json
result = json.dumps(main())
"""


async def preprocess_svc_callback(
    session,
    expected_outputs,
    new_binary_dir,
    platform,
    image_base,
    *,
    name,
    service,
):
    table = _load_yaml_mapping(Path(new_binary_dir) / f"cl_parsefuncs.{platform}.yaml")
    if not table:
        return False
    code = LOCATE.replace("TABLE_EA", str(int(table["gv_va"], 0))).replace(
        "SERVICE_NAME", repr(service.encode("ascii"))
    )
    located = parse_mcp_result(await session.call_tool("py_eval", {"code": code}))
    if not isinstance(located, dict) or located.get("pointer_size") != 4 or len(located.get("targets", [])) != 1:
        return False
    output = _output_for_symbol(expected_outputs, name)
    function = await _inspect_function_via_mcp(session, located["targets"][0], image_base, name)
    across = function is None
    if across:
        function = await _inspect_function_via_mcp(
            session,
            located["targets"][0],
            image_base,
            name,
            allow_across_function_boundary=True,
        )
    if not output or not function or not function.get("func_sig"):
        return False
    payload = {key: function[key] for key in ("func_name", "func_va", "func_rva", "func_size", "func_sig")}
    if across:
        payload["func_sig_allow_across_function_boundary"] = True
    write_func_yaml(output, payload)
    return True
