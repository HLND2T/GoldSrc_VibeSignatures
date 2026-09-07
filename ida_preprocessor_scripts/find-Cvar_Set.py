#!/usr/bin/env python3
"""Locate Cvar_Set, the public name/value cvar setter.

HL25 added cvarhook_t dispatch after Cvar_DirectSet. Official leak
engine/cvar.c has no hooks; the artifact follows Linux DWARF and names
the list cvar_hooks. GCC inlines the Cvar_Set body into
Cvar_SetValue and Cvar_CommandWithPrivilegeCheck, so
FULLMATCH "Cvar_Set: variable %s not found\\n" has three to four
function xrefs on Linux and one on Windows.

Cvar_Set is the unique owner whose only C-string data ref is that
diagnostic. The inlined copies also xref "%f"/"%d" or the command /
privilege strings. Discovery does not use a byte signature or old YAML.
"""

from pathlib import Path

from ida_analyze_util import (
    _inspect_function_via_mcp,
    _load_yaml_mapping,
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
CVAR_DIRECTSET_EA = CVAR_DIRECTSET_EA_PLACEHOLDER

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

def counted_c_string(ea):
    try:
        raw = idc.get_strlit_contents(int(ea))
    except Exception:
        return False
    if raw is None or len(raw) < 2:
        return False
    try:
        text = raw.decode('ascii')
    except Exception:
        return False
    return all(32 <= ord(ch) < 127 or ch in '\t\n\r' for ch in text)

def c_string_eas(func_start):
    found = set()
    for head in idautils.FuncItems(int(func_start)):
        for xref in idautils.DataRefsFrom(int(head)):
            if counted_c_string(int(xref)):
                found.add(int(xref))
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
    if len(survivors) > 1 and int(CVAR_DIRECTSET_EA):
        def resolves_to_direct(target_ea):
            seen = set()
            current = int(target_ea)
            expected = int(CVAR_DIRECTSET_EA)
            for _ in range(4):
                if current in seen:
                    return False
                seen.add(current)
                if current == expected:
                    return True
                name = (idc.get_func_name(current) or ida_name.get_name(current) or '')
                if 'Cvar_DirectSet' in name:
                    return True
                func = ida_funcs.get_func(current)
                if func is None:
                    return False
                size = int(func.end_ea) - int(func.start_ea)
                if size > 16:
                    return int(func.start_ea) == expected
                next_targets = []
                for head in idautils.FuncItems(int(func.start_ea)):
                    mnem = (idc.print_insn_mnem(int(head)) or '').lower()
                    if mnem not in ('call', 'jmp'):
                        continue
                    for xref in idautils.XrefsFrom(int(head), 0):
                        if xref.type in (idaapi.fl_CN, idaapi.fl_CF, idaapi.fl_JN, idaapi.fl_JF):
                            callee = ida_funcs.get_func(int(xref.to))
                            next_targets.append(int(callee.start_ea) if callee is not None else int(xref.to))
                if len(next_targets) != 1:
                    return False
                current = next_targets[0]
            return False

        calling = []
        leftover = []
        for rec in survivors:
            start = int(rec['ea'], 0)
            hits = False
            for ea in idautils.FuncItems(start):
                mnem = (idc.print_insn_mnem(int(ea)) or '').lower()
                if mnem not in ('call', 'jmp'):
                    continue
                for xref in idautils.XrefsFrom(int(ea), 0):
                    if xref.type in (idaapi.fl_CN, idaapi.fl_CF, idaapi.fl_JN, idaapi.fl_JF):
                        if resolves_to_direct(int(xref.to)):
                            hits = True
            if hits:
                calling.append(rec)
            else:
                leftover.append(rec)
        rejected.extend(leftover)
        survivors = calling
    if len(strings) != 1 or len(survivors) != 1:
        result = json.dumps({
            'error': 'Cvar_Set string owner is not unique',
            'cvar_directset': hex(int(CVAR_DIRECTSET_EA)),
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


def _function_ea_from_artifact(new_binary_dir, platform, func_name, image_base):
    artifact = _load_yaml_mapping(Path(new_binary_dir) / f"{func_name}.{platform}.yaml")
    if not artifact or artifact.get("func_name") != func_name:
        return None
    try:
        value = artifact["func_va"]
        func_ea = int(value, 0) if isinstance(value, str) else int(value)
    except (TypeError, ValueError, KeyError):
        return None
    return func_ea if func_ea >= int(image_base) else None


async def _locate_cvar_set(session, cvar_directset_ea=0):
    code = LOCATE_PY.replace("CVAR_DIRECTSET_EA_PLACEHOLDER", str(int(cvar_directset_ea or 0)))
    try:
        payload = parse_mcp_result(await session.call_tool("py_eval", {"code": code}))
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
    _ = skill_name, old_yaml_map
    if platform not in {"windows", "linux"}:
        return False
    output = _output_for_symbol(expected_outputs, TARGET_FUNCTION_NAME)
    if output is None:
        return False
    direct_ea = _function_ea_from_artifact(new_binary_dir, platform, "Cvar_DirectSet", image_base) or 0
    if debug:
        print(
            f"  find-Cvar_Set: Cvar_DirectSet ea={hex(direct_ea) if direct_ea else None} image_base={hex(int(image_base))}"
        )
    located = await _locate_cvar_set(session, direct_ea)
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
    allow_across = False
    if not function or not function.get("func_sig"):
        function = await _inspect_function_via_mcp(
            session,
            func_ea,
            image_base,
            TARGET_FUNCTION_NAME,
            allow_across_function_boundary=True,
        )
        allow_across = True
    if not function or not function.get("func_sig"):
        if debug:
            print(f"  find-Cvar_Set: function inspect failed ea={located.get('func_ea')}")
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
            f"owners={located.get('owner_count')} across={allow_across}"
        )
    payload = {
        "func_name": TARGET_FUNCTION_NAME,
        "func_va": function["func_va"],
        "func_rva": function["func_rva"],
        "func_size": function["func_size"],
        "func_sig": function["func_sig"],
    }
    if allow_across:
        payload["func_sig_allow_across_function_boundary"] = True
    write_func_yaml(output, payload)
    return True
