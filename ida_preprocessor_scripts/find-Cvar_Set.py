#!/usr/bin/env python3
"""Locate Cvar_Set, the public name/value cvar setter.

HL25 added cvarhook_t dispatch after Cvar_DirectSet. Official leak
engine/cvar.c has no hooks; Linux DWARF names the list cvar_hooks and
the registrar Cvar_HookVariable. GCC inlines the Cvar_Set body into
Cvar_SetValue and Cvar_CommandWithPrivilegeCheck, so
FULLMATCH "Cvar_Set: variable %s not found\\n" has three to four
function xrefs on Linux and one on Windows.

Cvar_Set is the unique owner whose only C-string data ref is that
diagnostic. The inlined copies also xref "%f"/"%d" or the command /
privilege strings. Discovery does not use a byte signature or old YAML.
"""

from ida_analyze_util import (
    _inspect_function_via_mcp,
    _output_for_symbol,
    parse_mcp_result,
    write_func_yaml,
)

TARGET_FUNCTION_NAME = "Cvar_Set"

LOCATE_PY = r"""
import ida_funcs
import ida_name
import ida_nalt
import idaapi
import idautils
import idc
import json
import traceback

CVAR_SET_MSG = 'Cvar_Set: variable %s not found\n'

def find_exact_strings(text):
    hits = []
    strings = idautils.Strings(default_setup=False)
    try:
        strings.setup(strtypes=[ida_nalt.STRTYPE_C], minlen=4)
    except Exception:
        pass
    for item in strings:
        if str(item) == text:
            hits.append(int(item.ea))
    return hits

def functions_for_string(sea):
    starts = []
    for xref in list(idautils.DataRefsTo(int(sea))) + list(idautils.CodeRefsTo(int(sea), 0)):
        func = ida_funcs.get_func(int(xref))
        if func is not None:
            starts.append(int(func.start_ea))
    return sorted(set(starts))

def c_string_eas(func_start):
    found = set()
    for head in idautils.FuncItems(int(func_start)):
        for xref in idautils.DataRefsFrom(int(head)):
            try:
                if idc.get_strlit_contents(int(xref)) is not None:
                    found.add(int(xref))
            except Exception:
                continue
    return sorted(found)

globals().update(locals())

try:
    if idaapi.inf_is_64bit():
        raise RuntimeError('expected 32-bit x86')
    strings = find_exact_strings(CVAR_SET_MSG)
    owners = []
    for sea in strings:
        owners.extend(functions_for_string(sea))
    owners = sorted(set(owners))
    survivors = []
    rejected = []
    for start in owners:
        string_eas = c_string_eas(start)
        rec = {
            'ea': hex(start),
            'name': idc.get_func_name(start) or '',
            'strings': [hex(ea) for ea in string_eas],
        }
        if len(strings) == 1 and string_eas == strings:
            survivors.append(rec)
        else:
            rejected.append(rec)
    if len(strings) != 1 or len(survivors) != 1:
        result = json.dumps({
            'error': 'Cvar_Set string owner is not unique',
            'string_count': len(strings),
            'owner_count': len(owners),
            'survivor_count': len(survivors),
            'survivors': survivors,
            'rejected': rejected,
        })
    else:
        start = int(survivors[0]['ea'], 0)
        try:
            ida_name.set_name(start, 'Cvar_Set', ida_name.SN_FORCE)
        except Exception:
            pass
        func = ida_funcs.get_func(start)
        result = json.dumps({
            'pointer_size': 4,
            'string_count': 1,
            'owner_count': len(owners),
            'func_ea': hex(start),
            'func_size': hex(int(func.end_ea) - start) if func else None,
        })
except Exception as exc:
    result = json.dumps({'error': str(exc), 'trace': traceback.format_exc()})
"""


async def _locate_cvar_set(session):
    try:
        payload = parse_mcp_result(await session.call_tool("py_eval", {"code": LOCATE_PY}))
    except Exception:  # noqa: BLE001 - MCP failures fail closed.
        return None
    if not isinstance(payload, dict):
        return None
    if payload.get("error") or payload.get("pointer_size") != 4:
        return payload if isinstance(payload, dict) else None
    try:
        string_count = int(payload.get("string_count") or 0)
    except (TypeError, ValueError):
        return None
    if string_count != 1:
        return payload
    if "func_ea" not in payload:
        return None
    return payload


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
    output = _output_for_symbol(expected_outputs, TARGET_FUNCTION_NAME)
    if output is None:
        return False
    located = await _locate_cvar_set(session)
    if located is None or located.get("error") or located.get("pointer_size") != 4:
        if debug:
            print(f"  find-Cvar_Set: locator failed {located}")
        return False
    try:
        func_ea = int(located["func_ea"], 0)
    except (TypeError, ValueError):
        return False
    if func_ea < int(image_base):
        return False
    function = await _inspect_function_via_mcp(session, func_ea, image_base, TARGET_FUNCTION_NAME)
    if not function or not function.get("func_sig"):
        return False
    try:
        inspected_va = int(function["func_va"], 0)
    except (TypeError, ValueError):
        return False
    if inspected_va != func_ea:
        return False
    if debug:
        print(
            f"  find-Cvar_Set: ea={located['func_ea']} size={located.get('func_size')} "
            f"owners={located.get('owner_count')}"
        )
    write_func_yaml(
        output,
        {
            "func_name": TARGET_FUNCTION_NAME,
            "func_va": function["func_va"],
            "func_rva": function["func_rva"],
            "func_size": function["func_size"],
            "func_sig": function["func_sig"],
        },
    )
    return True
