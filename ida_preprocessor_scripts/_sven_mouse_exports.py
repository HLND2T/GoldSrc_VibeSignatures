"""Locate mouse-input callbacks by exact exports or the verified client blob ABI."""

from ida_analyze_util import (
    _inspect_function_via_mcp,
    _output_for_symbol,
    parse_mcp_result,
    write_func_yaml,
)
from ida_preprocessor_scripts._client_blob_exports import locate_blob_client_entries

LOCATE_EXPORT = r"""
def main(target):
    import ida_funcs, ida_nalt, idaapi, idautils
    entries = {int(ea) for _, _, ea, name in idautils.Entries() if name == target}
    if idaapi.inf_is_64bit() or len(entries) != 1:
        return {'entry': None, 'input_path': ida_nalt.get_input_file_path()}
    entry = entries.pop()
    function = ida_funcs.get_func(entry)
    return {
        'entry': entry if function is not None and int(function.start_ea) == entry else None,
        'input_path': ida_nalt.get_input_file_path(),
    }
import json
result = json.dumps(main(TARGET))
"""


async def preprocess_export(session, expected_outputs, platform, image_base, target, debug=False, blob_fallback=False):
    if platform not in {"windows", "linux"}:
        return False
    output = _output_for_symbol(expected_outputs, target)
    if output is None:
        return False
    located = parse_mcp_result(await session.call_tool("py_eval", {"code": f"TARGET={target!r}\n" + LOCATE_EXPORT}))
    entry = located.get("entry") if isinstance(located, dict) else None
    if entry is None and blob_fallback and platform == "windows" and isinstance(located, dict):
        candidates = (await locate_blob_client_entries(session, located.get("input_path", ""), image_base)).get(target)
        if isinstance(candidates, list) and len(candidates) == 1:
            entry = candidates[0]
    if not isinstance(entry, int):
        if debug:
            print(f"  {target}: expected one exported x86 function entry: {located}")
        return False
    function = await _inspect_function_via_mcp(session, entry, image_base, target)
    if not function or not function.get("func_sig"):
        return False
    write_func_yaml(
        output,
        {key: function[key] for key in ("func_name", "func_va", "func_rva", "func_size", "func_sig")},
    )
    return True
