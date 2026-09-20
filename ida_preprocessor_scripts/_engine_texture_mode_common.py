"""Shared SvEngine helper for the gl_texturemode handler chain.

SvEngine keeps ``GL_TextureMode_f`` out of IDA's function list on both Windows
builds even though the bytes are analysed: the handler is reached only through
the address pushed into ``Cmd_AddCommand("gl_texturemode", ...)``, so no code
call ever reaches its entry. The Linux builds define it normally.

``recover_registered_owner`` finds that entry from the command registration and
``ensure_function_defined`` defines it in-memory. Every finder that revalidates
the handler must call the latter first, because the recovery is never saved: the
analysis pipeline runs restored-strict and leaves the IDB untouched, so the
definition has to be recreated inside each owned lifecycle.
"""

import json

from ida_analyze_util import parse_mcp_result

RECOVERY_COMMAND = "gl_texturemode"

RECOVER_PY = r"""
import ida_bytes, ida_funcs, ida_nalt, idautils, idc, idaapi, json

LITERAL = LITERAL_PLACEHOLDER
COMMAND = COMMAND_PLACEHOLDER


def string_table():
    strings = idautils.Strings(default_setup=False)
    strings.setup(strtypes=[ida_nalt.STRTYPE_C], minlen=4)
    return {str(item): int(item.ea) for item in strings}


try:
    table = string_table()
    sites = []
    for ea in [ea for text, ea in table.items() if text == LITERAL]:
        for xref in idautils.XrefsTo(ea, 0):
            if ida_bytes.is_code(ida_bytes.get_flags(int(xref.frm))):
                sites.append(int(xref.frm))
    sites = sorted(set(sites))
    owners = sorted({int(ida_funcs.get_func(site).start_ea) for site in sites if ida_funcs.get_func(site)})
    recovered = None
    if sites and not owners and COMMAND in table:
        for xref in idautils.XrefsTo(table[COMMAND], 0):
            site = int(xref.frm)
            if ida_funcs.get_func(site) is None:
                continue
            previous = idc.prev_head(site)
            if previous == idaapi.BADADDR:
                continue
            if (idc.print_insn_mnem(previous) or '').lower() != 'push':
                continue
            entry = idc.get_operand_value(previous, 0)
            if not ida_bytes.is_code(ida_bytes.get_flags(entry)):
                continue
            if not ida_funcs.add_func(entry):
                continue
            if all(int(ida_funcs.get_func(owner).start_ea) == entry for owner in sites):
                recovered = entry
            break
    result = json.dumps({
        'sites': [hex(site) for site in sites],
        'owners': [hex(owner) for owner in owners],
        'recovered': None if recovered is None else hex(recovered),
    })
except Exception as exc:
    result = json.dumps({'error': str(exc)})
"""

ENSURE_PY = r"""
import ida_funcs, json

EA = EA_PLACEHOLDER
existing = ida_funcs.get_func(EA)
if existing is not None and int(existing.start_ea) == EA:
    result = json.dumps({'defined': True, 'created': False, 'size': hex(int(existing.end_ea) - EA)})
else:
    created = bool(ida_funcs.add_func(EA))
    owner = ida_funcs.get_func(EA)
    result = json.dumps({
        'defined': bool(owner is not None and int(owner.start_ea) == EA),
        'created': created,
        'size': None if owner is None else hex(int(owner.end_ea) - EA),
    })
"""


async def recover_registered_owner(session, literal, debug=False):
    """Define and return the handler reached only through Cmd_AddCommand."""
    code = RECOVER_PY.replace("LITERAL_PLACEHOLDER", json.dumps(literal)).replace(
        "COMMAND_PLACEHOLDER", json.dumps(RECOVERY_COMMAND)
    )
    try:
        payload = parse_mcp_result(await session.call_tool("py_eval", {"code": code}))
    except Exception:  # noqa: BLE001 - recovery is best effort; the shared finder may still succeed.
        return None
    if not isinstance(payload, dict) or payload.get("error"):
        return None
    if debug:
        print(f"  texture-mode literal sites={payload['sites']} owners={payload['owners']}")
    recovered = payload.get("recovered")
    return None if recovered is None else int(recovered, 0)


async def ensure_function_defined(session, func_ea, expected_size=None, debug=False):
    """Define the handler when a previous no-save run created it only in memory."""
    code = ENSURE_PY.replace("EA_PLACEHOLDER", str(int(func_ea)))
    try:
        payload = parse_mcp_result(await session.call_tool("py_eval", {"code": code}))
    except Exception:  # noqa: BLE001 - MCP failures fail closed at the caller.
        return False
    if not isinstance(payload, dict) or not payload.get("defined"):
        return False
    size = payload.get("size")
    if expected_size is not None and size is not None and int(size, 16) != int(expected_size):
        if debug:
            print(f"  defined function size {size} does not match the artifact size {hex(int(expected_size))}")
        return False
    return True
