#!/usr/bin/env python3
"""Locate cvar_callbacks, the HL25 cvarhook_t list-head pointer.

Official Linux DWARF names the object cvar_hooks. MetaHook and this
artifact use cvar_callbacks. Cvar_Set walks the list after
Cvar_DirectSet; Cvar_HookVariable inserts. MetaHook's
mov eax,[absolute] scan of public Cvar_Set is only a Windows hint:
Linux GCC also loads inlined cvar_vars before the DirectSet call.

Owning function is Cvar_Set (find-Cvar_Set). Cvar_DirectSet is the
unique FULLMATCH "***PROTECTED***" function. The first non-executable
32-bit absolute load after that call is the list head. Discovery does
not use a byte signature or old YAML.
"""

from pathlib import Path

from ida_analyze_util import (
    _inspect_function_via_mcp,
    _load_yaml_mapping,
    _output_for_symbol,
    parse_mcp_result,
    write_gv_yaml,
)

TARGET_GV_NAME = "cvar_callbacks"
OWNER_FUNC_NAME = "Cvar_Set"

LOCATE_PY = r"""
import ida_bytes
import ida_funcs
import ida_name
import ida_nalt
import ida_segment
import idaapi
import idautils
import idc
import json
import traceback

PROTECTED = '***PROTECTED***'
CVAR_SET_EA = CVAR_SET_EA_PLACEHOLDER

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

def is_exec(ea):
    seg = ida_segment.getseg(int(ea))
    if seg is None:
        return False
    return bool(int(getattr(seg, 'perm', 0)) & int(getattr(ida_segment, 'SEGPERM_EXEC', 4)))

def seg_name(ea):
    seg = ida_segment.getseg(int(ea))
    return ida_segment.get_segm_name(seg) if seg else None

def insn_abs_mem(ea):
    insn = idautils.DecodeInstruction(int(ea))
    if not insn:
        return None
    raw = ida_bytes.get_bytes(int(ea), insn.size) or b''
    for op in insn.ops:
        if int(op.type) != int(idaapi.o_mem):
            continue
        value = int(op.addr) & 0xFFFFFFFF
        offb = int(getattr(op, 'offb', 0))
        if offb <= 0 or offb + 4 > insn.size:
            continue
        encoded = int.from_bytes(raw[offb:offb + 4], 'little', signed=False)
        if encoded != value:
            continue
        if is_exec(value) or (value & 3):
            continue
        if not ida_segment.getseg(value):
            continue
        return {
            'insn_ea': int(ea),
            'insn_len': int(insn.size),
            'insn_disp': offb,
            'gv_ea': value,
            'disasm': idc.generate_disasm_line(int(ea), 0) or '',
        }
    return None

def call_target(ea):
    insn = idautils.DecodeInstruction(int(ea))
    if not insn:
        return None
    mnem = (idc.print_insn_mnem(int(ea)) or '').lower()
    if mnem not in {'call', 'jmp'}:
        return None
    for xref in idautils.XrefsFrom(int(ea), 0):
        if xref.type in (idaapi.fl_CN, idaapi.fl_CF, idaapi.fl_JN, idaapi.fl_JF):
            func = ida_funcs.get_func(int(xref.to))
            if func is not None:
                return int(func.start_ea)
    return None

globals().update(locals())

try:
    if idaapi.inf_is_64bit():
        raise RuntimeError('expected 32-bit x86')
    owner = ida_funcs.get_func(int(CVAR_SET_EA))
    if owner is None or int(owner.start_ea) != int(CVAR_SET_EA):
        raise RuntimeError('Cvar_Set is not a function start')
    protected = find_exact_strings(PROTECTED)
    direct_owners = []
    for sea in protected:
        direct_owners.extend(functions_for_string(sea))
    direct_owners = sorted(set(direct_owners))
    if len(protected) < 1 or len(direct_owners) != 1:
        result = json.dumps({
            'error': 'Cvar_DirectSet is not unique',
            'protected_count': len(protected),
            'direct_count': len(direct_owners),
            'direct_owners': [hex(ea) for ea in direct_owners],
        })
    else:
        direct_ea = direct_owners[0]
        seen_direct = False
        loads = []
        ea = int(owner.start_ea)
        end = int(owner.end_ea)
        while ea < end:
            flags = ida_bytes.get_full_flags(ea)
            if ida_bytes.is_code(flags) and ida_bytes.is_head(flags):
                target = call_target(ea)
                if target == direct_ea:
                    seen_direct = True
                elif seen_direct:
                    match = insn_abs_mem(ea)
                    if match:
                        loads.append(match)
            next_ea = ida_bytes.next_head(ea, end)
            if next_ea == idaapi.BADADDR or next_ea <= ea:
                break
            ea = int(next_ea)
        unique = []
        seen_gv = set()
        for item in loads:
            if item['gv_ea'] not in seen_gv:
                seen_gv.add(item['gv_ea'])
                unique.append(item)
        if not seen_direct:
            result = json.dumps({
                'error': 'Cvar_Set does not call Cvar_DirectSet',
                'cvar_set': hex(int(owner.start_ea)),
                'cvar_directset': hex(direct_ea),
            })
        elif len(unique) != 1:
            result = json.dumps({
                'error': 'post-Cvar_DirectSet list head is not unique',
                'cvar_set': hex(int(owner.start_ea)),
                'cvar_directset': hex(direct_ea),
                'load_count': len(unique),
                'loads': [
                    {
                        'insn_ea': hex(item['insn_ea']),
                        'gv_ea': hex(item['gv_ea']),
                        'disasm': item['disasm'],
                    }
                    for item in unique
                ],
            })
        else:
            hit = unique[0]
            try:
                ida_name.set_name(int(hit['gv_ea']), 'cvar_callbacks', ida_name.SN_FORCE)
            except Exception:
                pass
            result = json.dumps({
                'pointer_size': 4,
                'cvar_set': hex(int(owner.start_ea)),
                'cvar_directset': hex(direct_ea),
                'gv_ea': hex(hit['gv_ea']),
                'gv_seg': seg_name(hit['gv_ea']),
                'insn_ea': hex(hit['insn_ea']),
                'insn_len': hit['insn_len'],
                'insn_disp': hit['insn_disp'],
                'insn_disasm': hit['disasm'],
            })
except Exception as exc:
    result = json.dumps({'error': str(exc), 'trace': traceback.format_exc()})
"""


def _cvar_set_artifact_path(new_binary_dir, platform):
    return Path(new_binary_dir) / f"{OWNER_FUNC_NAME}.{platform}.yaml"


async def _locate_cvar_callbacks(session, cvar_set_ea):
    code = LOCATE_PY.replace("CVAR_SET_EA_PLACEHOLDER", str(int(cvar_set_ea)))
    try:
        payload = parse_mcp_result(await session.call_tool("py_eval", {"code": code}))
    except Exception:  # noqa: BLE001 - MCP failures fail closed.
        return None
    if not isinstance(payload, dict):
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
    output = _output_for_symbol(expected_outputs, TARGET_GV_NAME)
    if output is None:
        return False
    owner = _load_yaml_mapping(_cvar_set_artifact_path(new_binary_dir, platform))
    if not owner:
        if debug:
            print("  find-cvar_callbacks: missing Cvar_Set artifact")
        return False
    try:
        owner_ea = int(owner["func_va"], 0)
    except (TypeError, ValueError, KeyError):
        return False
    if owner.get("func_name") != OWNER_FUNC_NAME or owner_ea < int(image_base):
        return False
    located = await _locate_cvar_callbacks(session, owner_ea)
    if located is None or located.get("error") or located.get("pointer_size") != 4:
        if debug:
            print(f"  find-cvar_callbacks: locator failed {located}")
        return False
    required = ("gv_ea", "insn_ea", "insn_len", "insn_disp")
    if any(field not in located for field in required):
        return False
    try:
        gv_ea = int(located["gv_ea"], 0)
        insn_ea = int(located["insn_ea"], 0)
        insn_len = int(located["insn_len"])
        insn_disp = int(located["insn_disp"])
    except (TypeError, ValueError):
        return False
    if gv_ea < int(image_base) or insn_ea < owner_ea:
        return False
    function = await _inspect_function_via_mcp(session, owner_ea, image_base, OWNER_FUNC_NAME)
    if not function or not function.get("func_sig"):
        return False
    try:
        func_va = int(function["func_va"], 0)
    except (TypeError, ValueError):
        return False
    if func_va != owner_ea:
        return False
    if debug:
        print(
            f"  find-cvar_callbacks: gv={located['gv_ea']} seg={located.get('gv_seg')} "
            f"insn={located['insn_ea']} {located.get('insn_disasm', '')}"
        )
    write_gv_yaml(
        output,
        {
            "gv_name": TARGET_GV_NAME,
            "gv_va": hex(gv_ea),
            "gv_rva": hex(gv_ea - int(image_base)),
            "gv_sig": function["func_sig"],
            "gv_sig_va": function["func_va"],
            "gv_inst_offset": hex(insn_ea - func_va),
            "gv_inst_length": hex(insn_len),
            "gv_inst_disp": hex(insn_disp),
        },
    )
    return True
