#!/usr/bin/env python3
"""Locate CS/CZ/CZDS GetClientColor without a discovery byte signature.

GCC clients retain the Itanium ABI symbol for GetClientColor(int). MSVC clients
have no symbol, so discovery follows references to the five known RGB color
arrays. The selector is the unique call-free function referring to all five.
A generated function signature is still emitted for runtime lookup; it is
never used to discover the function in the current IDB.
"""

from ida_analyze_util import _inspect_function_via_mcp, _output_for_symbol, parse_mcp_result, write_func_yaml

TARGET_FUNCTION_NAMES = ["GetClientColor"]
FIELDS = ("func_name", "func_va", "func_rva", "func_size", "func_sig")

LOCATE = r"""
import json

def locate():
    import ida_bytes, ida_funcs, ida_name, ida_segment, idaapi, idautils, idc, struct
    if idaapi.inf_is_64bit():
        return {'error': 'expected x86 IDB'}
    if PLATFORM == 'linux':
        address = ida_name.get_name_ea(idaapi.BADADDR, '_Z14GetClientColori')
        function = ida_funcs.get_func(address) if address != idaapi.BADADDR else None
        if function is None or int(function.start_ea) != address:
            return {'error': 'GetClientColor(int) symbol has no function entry'}
        return {'owner': int(address)}

    # These are the RGB values returned for CS and CZDS team/default colors.
    # Find each array independently; storage order and player layout may vary.
    colors = ((0.6, 0.8, 1.0), (1.0, 0.25, 0.25), (0.6, 1.0, 0.6),
              (1.0, 0.7, 0.0), (0.8, 0.8, 0.8))
    owners = None
    segments = []
    for start in idautils.Segments():
        segment = ida_segment.getseg(start)
        if segment is None or segment.perm & ida_segment.SEGPERM_EXEC:
            continue
        data = ida_bytes.get_bytes(int(segment.start_ea), int(segment.end_ea - segment.start_ea))
        if data is not None:
            segments.append((int(segment.start_ea), data))
    for color in colors:
        current = set()
        value = struct.pack('<fff', *color)
        for start, data in segments:
            offset = data.find(value)
            while offset >= 0:
                address = start + offset
                if address % 4 == 0:
                    for reference in idautils.DataRefsTo(address):
                        function = ida_funcs.get_func(reference)
                        if function is not None:
                            current.add(int(function.start_ea))
                offset = data.find(value, offset + 1)
        owners = current if owners is None else owners & current
    # The selector only reads the player team and returns a palette pointer.
    # Larger users can inline that logic, but also call other UI functions.
    owners = {
        owner for owner in owners
        if not any((idc.print_insn_mnem(item) or '').lower() == 'call' for item in idautils.FuncItems(owner))
    }
    if len(owners) != 1:
        return {'error': 'team-color selector is not unique', 'owners': sorted(owners)}
    return {'owner': owners.pop()}

result = json.dumps(locate())
"""


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
    _ = skill_name, old_yaml_map, new_binary_dir
    name = TARGET_FUNCTION_NAMES[0]
    output = _output_for_symbol(expected_outputs, name)
    if output is None or platform not in {"windows", "linux"}:
        return False
    raw = await session.call_tool("py_eval", {"code": LOCATE.replace("PLATFORM", repr(platform))})
    located = parse_mcp_result(raw)
    if not isinstance(located, dict) or not isinstance(located.get("owner"), int):
        if debug:
            print(f"  {name}: {located!r}; raw={raw!r}")
        return False
    candidate = await _inspect_function_via_mcp(session, located["owner"], image_base, name)
    across = candidate is None
    if across:
        candidate = await _inspect_function_via_mcp(
            session, located["owner"], image_base, name, allow_across_function_boundary=True
        )
    if candidate is None:
        if debug:
            print(f"  {name}: located function has no unique runtime signature")
        return False
    payload = {field: candidate[field] for field in FIELDS}
    if across:
        payload["func_sig_allow_across_function_boundary"] = True
    write_func_yaml(output, payload)
    return True
