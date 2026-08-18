#!/usr/bin/env python3
"""Locate cvar_hooks, the HL25 cvarhook_t list-head pointer.

Official Linux DWARF names the object cvar_hooks. Cvar_Set walks the
list after Cvar_DirectSet; Cvar_HookVariable inserts.

The finder consumes verified Cvar_Set and Cvar_DirectSet artifacts. It
requires one direct call from the former to the latter, then decodes the
immediate fall-through instruction as a writable 32-bit absolute load.
The reachable CFG must also use hook-node fields +4, +8, and +0 for the
cvar comparison, next link, and callback. Discovery does not use a byte
signature or old YAML.
"""

from pathlib import Path

from ida_analyze_util import (
    _inspect_function_via_mcp,
    _load_yaml_mapping,
    _output_for_symbol,
    parse_mcp_result,
    write_gv_yaml,
)

TARGET_GV_NAME = "cvar_hooks"
OWNER_FUNC_NAME = "Cvar_Set"
DIRECT_FUNC_NAME = "Cvar_DirectSet"

LOCATE_PY = r"""
import ida_bytes
import ida_funcs
import ida_gdl
import ida_idp
import ida_name
import ida_segment
import idaapi
import idautils
import idc
import json
import traceback

CVAR_SET_EA = CVAR_SET_EA_PLACEHOLDER
CVAR_DIRECTSET_EA = CVAR_DIRECTSET_EA_PLACEHOLDER
GPR32 = {'eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp', 'esp'}

def writable_data_segment(ea):
    seg = ida_segment.getseg(int(ea))
    if seg is None:
        return False
    perms = int(getattr(seg, 'perm', 0))
    executable = int(getattr(ida_segment, 'SEGPERM_EXEC', 4))
    writable = int(getattr(ida_segment, 'SEGPERM_WRITE', 2))
    return bool(perms & writable) and not bool(perms & executable)

def seg_name(ea):
    seg = ida_segment.getseg(int(ea))
    return ida_segment.get_segm_name(seg) if seg else None

def reg_name(op):
    if int(op.type) != int(idaapi.o_reg):
        return None
    try:
        return (ida_idp.get_reg_name(int(op.reg), 4) or '').lower()
    except Exception:
        return None

def memory_base_and_disp(op):
    op_type = int(op.type)
    if op_type not in (int(idaapi.o_phrase), int(idaapi.o_displ)):
        return None
    try:
        base = (ida_idp.get_reg_name(int(op.reg), 4) or '').lower()
    except Exception:
        return None
    if base not in GPR32:
        return None
    disp = 0 if op_type == int(idaapi.o_phrase) else int(op.addr) & 0xFFFFFFFF
    return base, disp

def absolute_dword_load(ea):
    insn = idautils.DecodeInstruction(int(ea))
    if not insn or (idc.print_insn_mnem(int(ea)) or '').lower() != 'mov':
        return None
    dst = insn.ops[0]
    src = insn.ops[1]
    dst_reg = reg_name(dst)
    if dst_reg not in GPR32 or int(src.type) != int(idaapi.o_mem):
        return None
    raw = ida_bytes.get_bytes(int(ea), insn.size) or b''
    value = int(src.addr) & 0xFFFFFFFF
    offb = int(getattr(src, 'offb', 0))
    if offb <= 0 or offb + 4 > insn.size:
        return None
    encoded = int.from_bytes(raw[offb:offb + 4], 'little', signed=False)
    if encoded != value or (value & 3) or not writable_data_segment(value):
        return None
    return {
        'insn_ea': int(ea),
        'insn_len': int(insn.size),
        'insn_disp': offb,
        'gv_ea': value,
        'node_reg': dst_reg,
        'disasm': idc.generate_disasm_line(int(ea), 0) or '',
    }

def direct_call_target(ea):
    insn = idautils.DecodeInstruction(int(ea))
    if not insn or (idc.print_insn_mnem(int(ea)) or '').lower() != 'call':
        return None
    targets = set()
    for xref in idautils.XrefsFrom(int(ea), 0):
        if xref.type in (idaapi.fl_CN, idaapi.fl_CF):
            func = ida_funcs.get_func(int(xref.to))
            if func is not None:
                targets.add(int(func.start_ea))
    return next(iter(targets)) if len(targets) == 1 else None

def reachable_heads(func, start_ea):
    flow = ida_gdl.FlowChart(func)
    blocks = list(flow)
    start_block = next(
        (block for block in blocks if int(block.start_ea) <= int(start_ea) < int(block.end_ea)),
        None,
    )
    if start_block is None:
        return []
    pending = [start_block]
    visited = set()
    heads = set()
    while pending:
        block = pending.pop()
        key = (int(block.start_ea), int(block.end_ea))
        if key in visited:
            continue
        visited.add(key)
        for ea in idautils.Heads(int(block.start_ea), int(block.end_ea)):
            if key == (int(start_block.start_ea), int(start_block.end_ea)) and int(ea) < int(start_ea):
                continue
            flags = ida_bytes.get_full_flags(int(ea))
            if ida_bytes.is_code(flags) and ida_bytes.is_head(flags):
                heads.add(int(ea))
        pending.extend(list(block.succs()))
    return sorted(heads)

def validate_hook_loop(func, load_ea, node_reg):
    compared_cvar = False
    advanced_next = False
    called_hook = False
    callback_regs = set()
    heads = reachable_heads(func, load_ea)
    for ea in heads:
        insn = idautils.DecodeInstruction(int(ea))
        if not insn:
            continue
        mnem = (idc.print_insn_mnem(int(ea)) or '').lower()
        operands = list(insn.ops)
        memory_operands = [memory_base_and_disp(op) for op in operands]
        if mnem == 'cmp' and (node_reg, 4) in memory_operands:
            compared_cvar = True
        if (
            mnem == 'mov'
            and reg_name(operands[0]) == node_reg
            and memory_base_and_disp(operands[1]) == (node_reg, 8)
        ):
            advanced_next = True
        if mnem == 'call' and memory_base_and_disp(operands[0]) == (node_reg, 0):
            called_hook = True
        if mnem == 'mov' and memory_base_and_disp(operands[1]) == (node_reg, 0):
            callback_reg = reg_name(operands[0])
            if callback_reg in GPR32:
                callback_regs.add(callback_reg)
        if mnem == 'call' and reg_name(operands[0]) in callback_regs:
            called_hook = True
    return {
        'compared_cvar': compared_cvar,
        'advanced_next': advanced_next,
        'called_hook': called_hook,
        'reachable_head_count': len(heads),
    }

globals().update(locals())

try:
    if idaapi.inf_is_64bit():
        raise RuntimeError('expected 32-bit x86')
    owner = ida_funcs.get_func(int(CVAR_SET_EA))
    if owner is None or int(owner.start_ea) != int(CVAR_SET_EA):
        raise RuntimeError('Cvar_Set is not a function start')
    direct = ida_funcs.get_func(int(CVAR_DIRECTSET_EA))
    if direct is None or int(direct.start_ea) != int(CVAR_DIRECTSET_EA):
        raise RuntimeError('Cvar_DirectSet is not a function start')
    calls = [
        int(ea)
        for ea in idautils.FuncItems(int(owner.start_ea))
        if direct_call_target(int(ea)) == int(direct.start_ea)
    ]
    if len(calls) != 1:
        result = json.dumps({
            'error': 'Cvar_Set direct call to Cvar_DirectSet is not unique',
            'cvar_set': hex(int(owner.start_ea)),
            'cvar_directset': hex(int(direct.start_ea)),
            'calls': [hex(ea) for ea in calls],
        })
    else:
        call_ea = calls[0]
        call_insn = idautils.DecodeInstruction(call_ea)
        fallthrough_ea = call_ea + int(call_insn.size) if call_insn else idaapi.BADADDR
        next_ea = ida_bytes.next_head(call_ea, int(owner.end_ea))
        if next_ea != fallthrough_ea:
            result = json.dumps({
                'error': 'Cvar_DirectSet fall-through is not the next instruction',
                'cvar_set': hex(int(owner.start_ea)),
                'cvar_directset': hex(int(direct.start_ea)),
                'call_ea': hex(call_ea),
                'fallthrough_ea': None if fallthrough_ea == idaapi.BADADDR else hex(fallthrough_ea),
                'next_ea': None if next_ea == idaapi.BADADDR else hex(int(next_ea)),
            })
        else:
            hit = absolute_dword_load(fallthrough_ea)
            hook_shape = None if hit is None else validate_hook_loop(owner, fallthrough_ea, hit['node_reg'])
            hook_shape_ok = bool(
                hook_shape
                and hook_shape.get('compared_cvar')
                and hook_shape.get('advanced_next')
                and hook_shape.get('called_hook')
            )
            if hit is None or not hook_shape_ok:
                result = json.dumps({
                    'error': 'Cvar_DirectSet fall-through is not the cvar hook-list load',
                    'cvar_set': hex(int(owner.start_ea)),
                    'cvar_directset': hex(int(direct.start_ea)),
                    'call_ea': hex(call_ea),
                    'fallthrough_ea': hex(fallthrough_ea),
                    'fallthrough_disasm': idc.generate_disasm_line(fallthrough_ea, 0) or '',
                    'hook_shape': hook_shape,
                })
            else:
                rename_ok = ida_name.set_name(int(hit['gv_ea']), 'cvar_hooks', ida_name.SN_FORCE)
                renamed_to = ida_name.get_name(int(hit['gv_ea'])) or ''
                if not rename_ok and renamed_to != 'cvar_hooks':
                    result = json.dumps({
                        'error': 'failed to rename hook-list global to cvar_hooks',
                        'gv_ea': hex(hit['gv_ea']),
                        'current_name': renamed_to,
                    })
                else:
                    result = json.dumps({
                        'pointer_size': 4,
                        'cvar_set': hex(int(owner.start_ea)),
                        'cvar_directset': hex(int(direct.start_ea)),
                        'call_ea': hex(call_ea),
                        'gv_ea': hex(hit['gv_ea']),
                        'gv_name': renamed_to,
                        'gv_seg': seg_name(hit['gv_ea']),
                        'insn_ea': hex(hit['insn_ea']),
                        'insn_len': hit['insn_len'],
                        'insn_disp': hit['insn_disp'],
                        'insn_disasm': idc.generate_disasm_line(int(hit['insn_ea']), 0) or '',
                        'hook_shape': hook_shape,
                    })
except Exception as exc:
    result = json.dumps({'error': str(exc), 'trace': traceback.format_exc()})
"""


def _function_artifact_path(new_binary_dir, platform, func_name):
    return Path(new_binary_dir) / f"{func_name}.{platform}.yaml"


def _function_ea_from_artifact(new_binary_dir, platform, func_name, image_base):
    artifact = _load_yaml_mapping(_function_artifact_path(new_binary_dir, platform, func_name))
    if not artifact or artifact.get("func_name") != func_name:
        return None
    try:
        value = artifact["func_va"]
        func_ea = int(value, 0) if isinstance(value, str) else int(value)
    except (TypeError, ValueError, KeyError):
        return None
    return func_ea if func_ea >= int(image_base) else None


async def _locate_cvar_hooks(session, cvar_set_ea, cvar_directset_ea):
    code = LOCATE_PY.replace("CVAR_SET_EA_PLACEHOLDER", str(int(cvar_set_ea))).replace(
        "CVAR_DIRECTSET_EA_PLACEHOLDER", str(int(cvar_directset_ea))
    )
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
    owner_ea = _function_ea_from_artifact(new_binary_dir, platform, OWNER_FUNC_NAME, image_base)
    direct_ea = _function_ea_from_artifact(new_binary_dir, platform, DIRECT_FUNC_NAME, image_base)
    if owner_ea is None or direct_ea is None:
        if debug:
            print("  find-cvar_hooks: missing Cvar_Set or Cvar_DirectSet artifact")
        return False
    owner_function = await _inspect_function_via_mcp(session, owner_ea, image_base, OWNER_FUNC_NAME)
    if not owner_function or not owner_function.get("func_sig"):
        if debug:
            print("  find-cvar_hooks: failed to verify Cvar_Set artifact")
        return False
    try:
        inspected_owner_ea = int(owner_function["func_va"], 0)
    except (TypeError, ValueError):
        return False
    if inspected_owner_ea != owner_ea:
        return False
    located = await _locate_cvar_hooks(session, owner_ea, direct_ea)
    if (
        located is None
        or located.get("error")
        or located.get("pointer_size") != 4
        or located.get("gv_name") != TARGET_GV_NAME
    ):
        if debug:
            print(f"  find-cvar_hooks: locator failed {located}")
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
    func_va = inspected_owner_ea
    if debug:
        print(
            f"  find-cvar_hooks: gv={located['gv_ea']} seg={located.get('gv_seg')} "
            f"insn={located['insn_ea']} {located.get('insn_disasm', '')}"
        )
    write_gv_yaml(
        output,
        {
            "gv_name": TARGET_GV_NAME,
            "gv_va": hex(gv_ea),
            "gv_rva": hex(gv_ea - int(image_base)),
            "gv_sig": owner_function["func_sig"],
            "gv_sig_va": owner_function["func_va"],
            "gv_inst_offset": hex(insn_ea - func_va),
            "gv_inst_length": hex(insn_len),
            "gv_inst_disp": hex(insn_disp),
        },
    )
    return True
