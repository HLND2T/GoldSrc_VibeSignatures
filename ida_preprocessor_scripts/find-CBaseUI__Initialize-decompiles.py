#!/usr/bin/env python3
"""Locate the client DLL factory slot used by CBaseUI::Initialize.

The shipped engines guard the client factory path with either
``cmp [absolute], 0`` or ``mov reg, [absolute]; test reg, reg``. The guard's
skip branch jumps over the unique ``VClientVGUI001`` factory call. This direct
locator avoids an unnecessary LLM dependency while preserving the verified
``CBaseUI__Initialize`` function signature as the runtime anchor.
"""

from pathlib import Path

from ida_analyze_util import (
    _inspect_function_via_mcp,
    _load_yaml_mapping,
    _output_for_symbol,
    parse_mcp_result,
    write_gv_yaml,
)


TARGET_GV_NAME = "g_pClientFactory"
OWNER_FUNC_NAME = "CBaseUI__Initialize"
CLIENT_VGUI_INTERFACE = "VClientVGUI001"


LOCATE_PY = r"""
import ida_bytes
import ida_funcs
import ida_segment
import idaapi
import idautils
import idc
import json
import traceback

OWNER_EA = OWNER_EA_PLACEHOLDER
TARGET_STRING = TARGET_STRING_PLACEHOLDER

def writable_data_segment(ea):
    seg = ida_segment.getseg(int(ea))
    if seg is None:
        return False
    perms = int(getattr(seg, 'perm', 0))
    writable = int(getattr(ida_segment, 'SEGPERM_WRITE', 2))
    return bool(perms & writable)

def seg_name(ea):
    seg = ida_segment.getseg(int(ea))
    return ida_segment.get_segm_name(seg) if seg else None

def register_id(op):
    return int(op.reg) if int(op.type) == int(idaapi.o_reg) else None

def encoded_absolute_memory(ea, op):
    if int(op.type) != int(idaapi.o_mem):
        return None
    insn = idautils.DecodeInstruction(int(ea))
    if not insn:
        return None
    value = int(op.addr) & 0xFFFFFFFF
    offb = int(getattr(op, 'offb', 0))
    raw = ida_bytes.get_bytes(int(ea), int(insn.size)) or b''
    if offb <= 0 or offb + 4 > int(insn.size):
        return None
    encoded = int.from_bytes(raw[offb:offb + 4], 'little', signed=False)
    if encoded != value or (value & 3) or not writable_data_segment(value):
        return None
    return {
        'gv_ea': value,
        'insn_ea': int(ea),
        'insn_len': int(insn.size),
        'insn_disp': offb,
        'insn_disasm': idc.generate_disasm_line(int(ea), 0) or '',
        'gv_seg': seg_name(value),
    }

def next_code_head(ea, end_ea):
    value = int(ida_bytes.next_head(int(ea), int(end_ea)))
    return None if value == int(idaapi.BADADDR) or value >= int(end_ea) else value

def next_zero_branch(ea, end_ea):
    cursor = int(ea)
    for _ in range(4):
        cursor = next_code_head(cursor, end_ea)
        if cursor is None:
            return None
        mnem = (idc.print_insn_mnem(cursor) or '').lower()
        if mnem in ('jz', 'je', 'jnz', 'jne'):
            return cursor
        if mnem not in ('mov', 'lea', 'nop'):
            return None
    return None

def zero_test_branch(owner, ea):
    insn = idautils.DecodeInstruction(int(ea))
    if not insn:
        return None
    mnem = (idc.print_insn_mnem(int(ea)) or '').lower()
    hit = None
    branch_ea = None
    if mnem == 'cmp':
        left, right = insn.ops[0], insn.ops[1]
        if int(right.type) != int(idaapi.o_imm) or int(right.value) != 0:
            return None
        hit = encoded_absolute_memory(int(ea), left)
        branch_ea = next_zero_branch(int(ea), int(owner.end_ea))
    elif mnem == 'mov':
        dst, src = insn.ops[0], insn.ops[1]
        dst_reg = register_id(dst)
        if dst_reg is None:
            return None
        hit = encoded_absolute_memory(int(ea), src)
        test_ea = next_code_head(int(ea), int(owner.end_ea))
        test_insn = idautils.DecodeInstruction(test_ea) if test_ea is not None else None
        test_mnem = (idc.print_insn_mnem(test_ea) or '').lower() if test_ea is not None else ''
        if not test_insn or test_mnem not in ('test', 'cmp'):
            return None
        left_reg = register_id(test_insn.ops[0])
        right = test_insn.ops[1]
        if left_reg != dst_reg:
            return None
        if test_mnem == 'test' and register_id(right) != dst_reg:
            return None
        if test_mnem == 'cmp' and (int(right.type) != int(idaapi.o_imm) or int(right.value) != 0):
            return None
        branch_ea = next_zero_branch(test_ea, int(owner.end_ea))
    if hit is None or branch_ea is None:
        return None
    branch_mnem = (idc.print_insn_mnem(branch_ea) or '').lower()
    if branch_mnem not in ('jz', 'je', 'jnz', 'jne'):
        return None
    targets = sorted(
        set(
            int(xref.to)
            for xref in idautils.XrefsFrom(branch_ea, 0)
            if xref.type in (idaapi.fl_JN, idaapi.fl_JF)
        )
    )
    if len(targets) != 1:
        return None
    hit['branch_ea'] = branch_ea
    hit['branch_target'] = targets[0]
    return hit

globals().update(locals())

try:
    if idaapi.inf_is_64bit():
        raise RuntimeError('expected 32-bit x86')
    owner = ida_funcs.get_func(int(OWNER_EA))
    if owner is None or int(owner.start_ea) != int(OWNER_EA):
        raise RuntimeError('CBaseUI__Initialize is not a function start')
    string_eas = []
    for item in idautils.Strings():
        if str(item) == TARGET_STRING:
            string_eas.append(int(item.ea))
    string_xref_set = set()
    for string_ea in string_eas:
        for xref in idautils.XrefsTo(string_ea, 0):
            func = ida_funcs.get_func(int(xref.frm))
            if func is not None and int(func.start_ea) == int(owner.start_ea):
                string_xref_set.add(int(xref.frm))
    string_xrefs = sorted(string_xref_set)
    if len(string_xrefs) != 1:
        result = json.dumps({
            'error': 'VClientVGUI001 xref is not unique in CBaseUI__Initialize',
            'owner_ea': hex(int(owner.start_ea)),
            'string_eas': [hex(ea) for ea in string_eas],
            'string_xrefs': [hex(ea) for ea in string_xrefs],
        })
    else:
        string_xref = string_xrefs[0]
        candidates = []
        for ea in idautils.FuncItems(int(owner.start_ea)):
            ea = int(ea)
            if not (0 < string_xref - ea <= 0x100):
                continue
            hit = zero_test_branch(owner, ea)
            if hit is None or not (ea < string_xref < int(hit['branch_target'])):
                continue
            candidates.append(hit)
        if len(candidates) != 1:
            result = json.dumps({
                'error': 'client factory guard is not unique',
                'owner_ea': hex(int(owner.start_ea)),
                'string_xref': hex(string_xref),
                'candidate_count': len(candidates),
                'candidates': candidates,
            })
        else:
            result = json.dumps({
                'pointer_size': 4,
                'owner_ea': hex(int(owner.start_ea)),
                'string_xref': hex(string_xref),
                **candidates[0],
            })
except Exception as exc:
    result = json.dumps({'error': str(exc), 'trace': traceback.format_exc()})
"""


def _owner_artifact(new_binary_dir, platform):
    path = Path(new_binary_dir) / f"{OWNER_FUNC_NAME}.{platform}.yaml"
    artifact = _load_yaml_mapping(path)
    if not artifact or artifact.get("func_name") != OWNER_FUNC_NAME:
        return None
    try:
        func_ea = int(artifact["func_va"], 0)
    except (KeyError, TypeError, ValueError):
        return None
    return artifact, func_ea


async def _locate_client_factory(session, owner_ea):
    code = LOCATE_PY.replace("OWNER_EA_PLACEHOLDER", str(int(owner_ea))).replace(
        "TARGET_STRING_PLACEHOLDER", repr(CLIENT_VGUI_INTERFACE)
    )
    try:
        payload = parse_mcp_result(await session.call_tool("py_eval", {"code": code}))
    except Exception:  # noqa: BLE001 - MCP failures fail closed.
        return None
    return payload if isinstance(payload, dict) else None


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
    owner_artifact = _owner_artifact(new_binary_dir, platform)
    if output is None or owner_artifact is None:
        if debug:
            print("  find-CBaseUI__Initialize-decompiles: missing output or owner artifact")
        return False
    artifact, owner_ea = owner_artifact
    allow_across = bool(artifact.get("func_sig_allow_across_function_boundary"))
    owner_function = await _inspect_function_via_mcp(
        session,
        owner_ea,
        image_base,
        OWNER_FUNC_NAME,
        allow_across_function_boundary=allow_across,
    )
    if not owner_function or not owner_function.get("func_sig"):
        return False
    try:
        inspected_owner_ea = int(owner_function["func_va"], 0)
    except (KeyError, TypeError, ValueError):
        return False
    if inspected_owner_ea != owner_ea:
        return False
    located = await _locate_client_factory(session, owner_ea)
    if located is None or located.get("error") or located.get("pointer_size") != 4:
        if debug:
            print(f"  find-CBaseUI__Initialize-decompiles: direct locator failed {located}")
        return False
    try:
        located_owner_ea = int(located["owner_ea"], 0)
        gv_ea = int(located["gv_ea"])
        insn_ea = int(located["insn_ea"])
        insn_len = int(located["insn_len"])
        insn_disp = int(located["insn_disp"])
    except (KeyError, TypeError, ValueError):
        return False
    if located_owner_ea != owner_ea or gv_ea < int(image_base) or insn_ea < owner_ea:
        return False
    payload = {
        "gv_name": TARGET_GV_NAME,
        "gv_va": hex(gv_ea),
        "gv_rva": hex(gv_ea - int(image_base)),
        "gv_sig": owner_function["func_sig"],
        "gv_sig_va": owner_function["func_va"],
        "gv_inst_offset": hex(insn_ea - owner_ea),
        "gv_inst_length": hex(insn_len),
        "gv_inst_disp": hex(insn_disp),
    }
    if allow_across:
        payload["gv_sig_allow_across_function_boundary"] = True
    if debug:
        print(
            f"  find-CBaseUI__Initialize-decompiles: {TARGET_GV_NAME}={located['gv_ea']} "
            f"seg={located.get('gv_seg')} insn={located['insn_ea']} {located.get('insn_disasm', '')}"
        )
    write_gv_yaml(output, payload)
    return True
