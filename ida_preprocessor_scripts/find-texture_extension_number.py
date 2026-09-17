#!/usr/bin/env python3
"""Locate the legacy texture-name counter from GL_LoadTexture2.

Blob-era engines assign the current ``texture_extension_number`` to the new
gltexture_t slot, increment that same global by one, and store it back.  The
finder consumes the verified GL_LoadTexture2 artifact and requires that data
flow to identify exactly one writable dword initialized to one.  Newer engines
use GL_GenTexture/glGenTextures and do not register this Windows-only finder.
"""

from pathlib import Path

from ida_analyze_util import (
    _inspect_function_via_mcp,
    _load_yaml_mapping,
    _output_for_symbol,
    gv_resolution_fields_via_mcp,
    parse_mcp_result,
    write_gv_yaml,
)

TARGET_GV_NAME = "texture_extension_number"
OWNER_FUNC_NAME = "GL_LoadTexture2"

LOCATE_PY = r"""
import ida_bytes
import ida_funcs
import ida_idp
import ida_segment
import idaapi
import idautils
import idc
import json
import traceback

OWNER_EA = OWNER_EA_PLACEHOLDER
VALUE_STORE_WINDOW = 6
UPDATE_WINDOW = 12


def is_writable_data(ea):
    seg = ida_segment.getseg(int(ea))
    if seg is None or int(ea) == 0:
        return False
    perms = int(getattr(seg, 'perm', 0))
    writable = int(getattr(ida_segment, 'SEGPERM_WRITE', 2))
    executable = int(getattr(ida_segment, 'SEGPERM_EXEC', 4))
    return bool(perms & writable) and not bool(perms & executable)


def seg_name(ea):
    seg = ida_segment.getseg(int(ea))
    return ida_segment.get_segm_name(seg) if seg else None


def reg_name(op):
    try:
        return (ida_idp.get_reg_name(int(op.reg), 4) or '').lower()
    except Exception:
        return None


def absolute_targets(ea):
    targets = set()
    for ref in idautils.DataRefsFrom(int(ea)):
        if is_writable_data(ref):
            targets.add(int(ref))
    insn = idautils.DecodeInstruction(int(ea))
    if not insn:
        return targets
    for op in insn.ops:
        op_type = int(op.type)
        if op_type == int(idaapi.o_void):
            break
        value = None
        if op_type == int(idaapi.o_mem):
            value = int(op.addr) & 0xFFFFFFFF
        elif op_type == int(idaapi.o_imm):
            value = int(op.value) & 0xFFFFFFFF
        if value is not None and is_writable_data(value):
            targets.add(value)
    return targets


def register_load(entry):
    insn = entry['insn']
    if entry['mnem'] != 'mov' or int(insn.ops[0].type) != int(idaapi.o_reg):
        return None
    if int(insn.ops[1].type) not in (int(idaapi.o_mem), int(idaapi.o_displ), int(idaapi.o_phrase)):
        return None
    targets = absolute_targets(entry['ea'])
    if len(targets) != 1:
        return None
    target = next(iter(targets))
    if int(ida_bytes.get_dword(target)) != 1:
        return None
    return reg_name(insn.ops[0]), target, int(getattr(insn.ops[1], 'offb', 0) or 0)


def stores_register_to_slot(entry, register):
    insn = entry['insn']
    if entry['mnem'] != 'mov':
        return False
    if int(insn.ops[0].type) not in (int(idaapi.o_displ), int(idaapi.o_phrase)):
        return False
    if int(insn.ops[1].type) != int(idaapi.o_reg) or reg_name(insn.ops[1]) != register:
        return False
    return int(getattr(insn.ops[0], 'addr', 0) or 0) == 0


def incremented_register(entry, register):
    insn = entry['insn']
    if entry['mnem'] == 'inc':
        return int(insn.ops[0].type) == int(idaapi.o_reg) and reg_name(insn.ops[0]) == register
    if entry['mnem'] != 'add':
        return False
    return (int(insn.ops[0].type) == int(idaapi.o_reg)
            and reg_name(insn.ops[0]) == register
            and int(insn.ops[1].type) == int(idaapi.o_imm)
            and int(insn.ops[1].value) == 1)


def writes_register_to_global(entry, register, target):
    insn = entry['insn']
    if entry['mnem'] != 'mov' or int(insn.ops[0].type) != int(idaapi.o_mem):
        return False
    if int(insn.ops[1].type) != int(idaapi.o_reg) or reg_name(insn.ops[1]) != register:
        return False
    return int(target) in absolute_targets(entry['ea'])


globals().update(locals())

try:
    if idaapi.inf_is_64bit():
        raise RuntimeError('expected 32-bit x86')
    owner = ida_funcs.get_func(int(OWNER_EA))
    if owner is None or int(owner.start_ea) != int(OWNER_EA):
        raise RuntimeError('GL_LoadTexture2 is not a function start')
    entries = []
    for ea in idautils.FuncItems(int(owner.start_ea)):
        insn = idautils.DecodeInstruction(int(ea))
        if not insn:
            continue
        entries.append({
            'ea': int(ea),
            'insn': insn,
            'mnem': (idc.print_insn_mnem(int(ea)) or '').lower(),
        })
    candidates = []
    for index, entry in enumerate(entries):
        loaded = register_load(entry)
        if loaded is None:
            continue
        value_register, target, disp = loaded
        if not disp:
            continue
        value_store_index = None
        for cursor in range(index + 1, min(len(entries), index + 1 + VALUE_STORE_WINDOW)):
            if stores_register_to_slot(entries[cursor], value_register):
                value_store_index = cursor
                break
        if value_store_index is None:
            continue
        update_register = value_register
        increment_index = None
        writeback_index = None
        for cursor in range(value_store_index + 1, min(len(entries), value_store_index + 1 + UPDATE_WINDOW)):
            second_load = register_load(entries[cursor])
            if second_load is not None and second_load[1] == target:
                update_register = second_load[0]
            if incremented_register(entries[cursor], update_register):
                increment_index = cursor
                continue
            if increment_index is not None and writes_register_to_global(entries[cursor], update_register, target):
                writeback_index = cursor
                break
        if writeback_index is None:
            continue
        candidates.append({
            'gv_ea': target,
            'insn_ea': entry['ea'],
            'insn_len': int(entry['insn'].size),
            'insn_disp': disp,
            'insn_disasm': idc.generate_disasm_line(entry['ea'], 0) or '',
            'slot_store_ea': entries[value_store_index]['ea'],
            'increment_ea': entries[increment_index]['ea'],
            'writeback_ea': entries[writeback_index]['ea'],
            'gv_seg': seg_name(target),
        })
    unique = {}
    for candidate in candidates:
        unique[candidate['gv_ea']] = candidate
    candidates = list(unique.values())
    if len(candidates) != 1:
        result = json.dumps({
            'error': 'texture_extension_number candidate is not unique',
            'candidate_count': len(candidates),
            'candidates': [
                {key: (hex(value) if isinstance(value, int) else value) for key, value in candidate.items()}
                for candidate in candidates
            ],
        })
    else:
        candidate = candidates[0]
        result = json.dumps({
            'pointer_size': 4,
            'owner_ea': hex(int(owner.start_ea)),
            'owner_end': hex(int(owner.end_ea)),
            **{
                key: (hex(value) if isinstance(value, int) else value)
                for key, value in candidate.items()
            },
        })
except Exception as exc:
    result = json.dumps({'error': str(exc), 'trace': traceback.format_exc()})
"""


def _owner_artifact(new_binary_dir, platform, image_base):
    artifact = _load_yaml_mapping(Path(new_binary_dir) / f"{OWNER_FUNC_NAME}.{platform}.yaml")
    if not artifact or artifact.get("func_name") != OWNER_FUNC_NAME:
        return None
    try:
        owner_ea = int(artifact["func_va"], 0)
    except (KeyError, TypeError, ValueError):
        return None
    if owner_ea < int(image_base):
        return None
    return artifact, owner_ea


async def _locate(session, owner_ea):
    code = LOCATE_PY.replace("OWNER_EA_PLACEHOLDER", str(int(owner_ea)))
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
    if platform != "windows":
        return False
    output = _output_for_symbol(expected_outputs, TARGET_GV_NAME)
    owner = _owner_artifact(new_binary_dir, platform, image_base)
    if output is None or owner is None:
        if debug:
            print("  find-texture_extension_number: missing output or GL_LoadTexture2 artifact")
        return False
    owner_data, owner_ea = owner
    located = await _locate(session, owner_ea)
    if located is None or located.get("error") or located.get("pointer_size") != 4:
        if debug:
            print(f"  find-texture_extension_number: locator failed {located}")
        return False
    try:
        insn_ea = int(located["insn_ea"], 0)
        insn_len = int(located["insn_len"], 0) if isinstance(located["insn_len"], str) else int(located["insn_len"])
        insn_disp = int(located["insn_disp"], 0) if isinstance(located["insn_disp"], str) else int(located["insn_disp"])
        gv_ea = int(located["gv_ea"], 0)
        owner_end = int(located["owner_end"], 0)
    except (KeyError, TypeError, ValueError):
        return False
    if not (owner_ea <= insn_ea < owner_end) or gv_ea < int(image_base):
        return False
    function = await _inspect_function_via_mcp(
        session,
        owner_ea,
        image_base,
        OWNER_FUNC_NAME,
        allow_across_function_boundary=bool(owner_data.get("func_sig_allow_across_function_boundary")),
    )
    if not function or not function.get("func_sig") or int(function["func_va"], 0) != owner_ea:
        return False
    resolution = await gv_resolution_fields_via_mcp(session, insn_ea, insn_disp, gv_ea, image_base, platform)
    if resolution is None or resolution:
        return False
    if debug:
        print(
            f"  find-texture_extension_number: gv={hex(gv_ea)} insn={hex(insn_ea)} "
            f"writeback={located.get('writeback_ea')} {located.get('insn_disasm', '')}"
        )
    payload = {
        "gv_name": TARGET_GV_NAME,
        "gv_va": hex(gv_ea),
        "gv_rva": hex(gv_ea - int(image_base)),
        "gv_sig": function["func_sig"],
        "gv_sig_va": function["func_va"],
        "gv_inst_offset": hex(insn_ea - owner_ea),
        "gv_inst_length": hex(insn_len),
        "gv_inst_disp": hex(insn_disp),
    }
    if function.get("func_sig_allow_across_function_boundary"):
        payload["gv_sig_allow_across_function_boundary"] = True
    write_gv_yaml(output, payload)
    return True
