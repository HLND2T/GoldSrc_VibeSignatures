"""Locate Sven mouse-input callbacks by their exact public client exports."""

from ida_analyze_util import (
    _inspect_function_via_mcp,
    _output_for_symbol,
    parse_mcp_result,
    write_func_yaml,
)

LOCATE_EXPORT = r"""
def main(target):
    import ida_funcs, idaapi, idautils
    entries = {int(ea) for _, _, ea, name in idautils.Entries() if name == target}
    if idaapi.inf_is_64bit() or len(entries) != 1:
        return None
    entry = entries.pop()
    function = ida_funcs.get_func(entry)
    return entry if function is not None and int(function.start_ea) == entry else None
import json
result = json.dumps({'entry': main(TARGET)})
"""


async def preprocess_export(session, expected_outputs, platform, image_base, target, debug=False):
    if platform not in {"windows", "linux"}:
        return False
    output = _output_for_symbol(expected_outputs, target)
    if output is None:
        return False
    located = parse_mcp_result(await session.call_tool("py_eval", {"code": f"TARGET={target!r}\n" + LOCATE_EXPORT}))
    if not isinstance(located, dict) or not isinstance(located.get("entry"), int):
        if debug:
            print(f"  {target}: expected one exported x86 function entry: {located}")
        return False
    function = await _inspect_function_via_mcp(session, located["entry"], image_base, target)
    if not function or not function.get("func_sig"):
        return False
    write_func_yaml(
        output,
        {key: function[key] for key in ("func_name", "func_va", "func_rva", "func_size", "func_sig")},
    )
    return True
