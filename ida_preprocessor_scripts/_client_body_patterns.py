"""Validate budgeted client body patterns and inspect their explicit owners.

Discovery stays inside a decoded function. Explicit entry patterns may opt in
to the shared inspector's recovery of missing function metadata. Only the output signature
may cross its boundary when operand wildcarding makes a short body ambiguous.
All grouped results are validated before any output is written.
"""

from ida_analyze_util import (
    _find_byte_matches,
    _inspect_function_via_mcp,
    _output_for_symbol,
    parse_mcp_result,
    write_func_yaml,
)

FIELDS = ("func_name", "func_sig", "func_va", "func_rva", "func_size")
LOCATE_OWNER = r"""
def locate(values):
    import ida_bytes, ida_funcs, idaapi
    hit = values['hit']
    flags = ida_bytes.get_full_flags(hit)
    function = ida_funcs.get_func(hit)
    if idaapi.inf_is_64bit():
        return None
    if function is None:
        return hit if values['entry_anchor'] else None
    if values['entry_anchor'] and int(function.start_ea) != hit:
        return None
    if (not ida_bytes.is_code(flags) or not ida_bytes.is_head(flags)
            or hit + values['length'] > int(function.end_ea)):
        return None
    return int(function.start_ea)
import json
result = json.dumps({'owner': locate(VALUES)})
"""


async def preprocess_body_patterns(
    session, expected_outputs, signatures_by_name, image_base, debug=False, *, entry_names=()
):
    outputs = {}
    for name, signatures in signatures_by_name.items():
        for signature in signatures:
            matches = await _find_byte_matches(session, signature, limit=2)
            if matches is None or len(matches) > 1:
                if debug:
                    print(f"  {name}: failed or ambiguous discovery pattern: {matches}")
                return False
            if matches:
                break
        else:
            if debug:
                print(f"  {name}: no validated body pattern matched")
            return False
        values = {"hit": matches[0], "length": len(signature.split()), "entry_anchor": name in entry_names}
        located = parse_mcp_result(
            await session.call_tool("py_eval", {"code": LOCATE_OWNER.replace("VALUES", repr(values))})
        )
        if not isinstance(located, dict) or not isinstance(located.get("owner"), int):
            if debug:
                print(f"  {name}: pattern has no validated owner: {located}")
            return False
        candidate = await _inspect_function_via_mcp(session, located["owner"], image_base, name)
        across = candidate is None
        if across:
            candidate = await _inspect_function_via_mcp(
                session, located["owner"], image_base, name, allow_across_function_boundary=True
            )
        if candidate is None:
            if debug:
                print(f"  {name}: explicit owner cannot produce a unique function signature")
            return False
        output = _output_for_symbol(expected_outputs, name)
        if output is None:
            return False
        outputs[output] = {field: candidate[field] for field in FIELDS}
        if across:
            outputs[output]["func_sig_allow_across_function_boundary"] = True
    for output, candidate in outputs.items():
        write_func_yaml(output, candidate)
    return True
