#!/usr/bin/env python3
"""Locate the engine particle-list head from R_DrawParticles.

R_DrawParticles passes ``&active_particles`` to R_FreeDeadParticles and then
immediately loads the same writable pointer slot as the head of its particle
loop.  The locator consumes the already-verified R_DrawParticles artifact and
requires that address-of -> direct call -> same-slot load -> null-test shape to
be unique.  It accepts Windows absolute operands, GoldSrc Linux absolute
operands, and SvEngine Linux GOTOFF operands without relying on one register or
one instruction encoding.
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

TARGET_GV_NAME = "active_particles"
OWNER_FUNC_NAME = "R_DrawParticles"

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
POST_CALL_WINDOW = 4


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


def pic_anchor(func_start):
    ea = int(func_start)
    for _ in range(12):
        insn = idautils.DecodeInstruction(ea)
        if not insn or insn.size <= 0:
            return None
        raw = ida_bytes.get_bytes(ea, insn.size) or b''
        if len(raw) >= 6 and raw[0] == 0x81 and raw[1] == 0xC3:
            imm = int.from_bytes(raw[2:6], 'little', signed=True)
            return (ea + imm) & 0xFFFFFFFF
        ea += insn.size
    return None


def pic_operand(ea, ebx_base):
    if ebx_base is None:
        return None
    insn = idautils.DecodeInstruction(int(ea))
    if not insn or insn.size < 6:
        return None
    raw = ida_bytes.get_bytes(int(ea), int(insn.size)) or b''
    if not raw or raw[0] not in (0x8B, 0x8D):
        return None
    modrm = raw[1]
    if (modrm >> 6) != 2:
        return None
    rm = modrm & 7
    if rm == 3:
        off = 2
    elif rm == 4 and len(raw) >= 7 and (raw[2] & 7) == 3:
        off = 3
    else:
        return None
    disp = int.from_bytes(raw[off:off + 4], 'little', signed=True)
    resolved = (int(ebx_base) + disp) & 0xFFFFFFFF
    return {'off': off, 'resolved': resolved}


def resolved_targets(ea, ebx_base):
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
    info = pic_operand(ea, ebx_base)
    if info and is_writable_data(info['resolved']):
        targets.add(int(info['resolved']))
    return targets


def direct_call_target(ea):
    if (idc.print_insn_mnem(int(ea)) or '').lower() != 'call':
        return None
    target = int(idc.get_operand_value(int(ea), 0))
    fn = ida_funcs.get_func(target)
    if fn is None or int(fn.start_ea) != target:
        return None
    return target


def load_register(ea):
    insn = idautils.DecodeInstruction(int(ea))
    if not insn or (idc.print_insn_mnem(int(ea)) or '').lower() != 'mov':
        return None
    if int(insn.ops[0].type) != int(idaapi.o_reg):
        return None
    if int(insn.ops[1].type) not in (int(idaapi.o_mem), int(idaapi.o_displ), int(idaapi.o_phrase)):
        return None
    return reg_name(insn.ops[0])


def address_materialization(ea):
    insn = idautils.DecodeInstruction(int(ea))
    if not insn:
        return False
    mnem = (idc.print_insn_mnem(int(ea)) or '').lower()
    if mnem in ('lea', 'push'):
        return True
    if mnem != 'mov':
        return False
    return (int(insn.ops[0].type) in (int(idaapi.o_mem), int(idaapi.o_displ), int(idaapi.o_phrase))
            and int(insn.ops[1].type) == int(idaapi.o_imm))


globals().update(locals())

try:
    if idaapi.inf_is_64bit():
        raise RuntimeError('expected 32-bit x86')
    owner = ida_funcs.get_func(int(OWNER_EA))
    if owner is None or int(owner.start_ea) != int(OWNER_EA):
        raise RuntimeError('R_DrawParticles is not a function start')
    ebx_base = pic_anchor(int(owner.start_ea))
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
    call_counts = {}
    for entry in entries:
        target = direct_call_target(entry['ea'])
        if target is not None:
            call_counts[target] = call_counts.get(target, 0) + 1
    candidates = []
    diagnostics = []
    for call_index, entry in enumerate(entries):
        call_target = direct_call_target(entry['ea'])
        if call_target is None:
            continue
        argument_start = 0
        for prior_index in range(call_index - 1, -1, -1):
            if entries[prior_index]['mnem'] == 'call':
                argument_start = prior_index + 1
                break
        before = entries[argument_start:call_index]
        address_targets = set()
        for prior in before:
            if address_materialization(prior['ea']):
                address_targets.update(resolved_targets(prior['ea'], ebx_base))
        if not address_targets:
            continue
        diagnostic = {
            'call_ea': hex(entry['ea']),
            'call_target': hex(call_target),
            'address_targets': [hex(value) for value in sorted(address_targets)],
            'following': [],
        }
        for load_index in range(call_index + 1, min(len(entries), call_index + 1 + POST_CALL_WINDOW)):
            load = entries[load_index]
            register = load_register(load['ea'])
            diagnostic['following'].append({
                'ea': hex(load['ea']),
                'disasm': idc.generate_disasm_line(load['ea'], 0) or '',
                'register': register,
                'targets': [hex(value) for value in sorted(resolved_targets(load['ea'], ebx_base))],
            })
            if register is None:
                continue
            common = address_targets & resolved_targets(load['ea'], ebx_base)
            if len(common) != 1:
                continue
            load_insn = load['insn']
            disp = int(getattr(load_insn.ops[1], 'offb', 0) or 0)
            if not disp:
                continue
            gv_ea = next(iter(common))
            candidates.append({
                'gv_ea': gv_ea,
                'call_ea': entry['ea'],
                'call_target': call_target,
                'call_count': call_counts[call_target],
                'insn_ea': load['ea'],
                'insn_len': int(load_insn.size),
                'insn_disp': disp,
                'insn_disasm': idc.generate_disasm_line(load['ea'], 0) or '',
                'gv_seg': seg_name(gv_ea),
                'pic_base': ebx_base,
            })
        diagnostics.append(diagnostic)
    unique = {}
    for candidate in candidates:
        unique[(candidate['gv_ea'], candidate['insn_ea'])] = candidate
    candidates = list(unique.values())
    if len(candidates) != 1:
        result = json.dumps({
            'error': 'active_particles candidate is not unique',
            'candidate_count': len(candidates),
            'diagnostics': diagnostics,
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
    if platform not in {"windows", "linux"}:
        return False
    output = _output_for_symbol(expected_outputs, TARGET_GV_NAME)
    owner = _owner_artifact(new_binary_dir, platform, image_base)
    if output is None or owner is None:
        if debug:
            print("  find-active_particles: missing output or R_DrawParticles artifact")
        return False
    owner_data, owner_ea = owner
    located = await _locate(session, owner_ea)
    if located is None or located.get("error") or located.get("pointer_size") != 4:
        if debug:
            print(f"  find-active_particles: locator failed {located}")
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
    if resolution is None:
        return False
    if debug:
        print(
            f"  find-active_particles: gv={hex(gv_ea)} insn={hex(insn_ea)} "
            f"{located.get('insn_disasm', '')} call={located.get('call_ea')}"
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
        **resolution,
    }
    if function.get("func_sig_allow_across_function_boundary"):
        payload["gv_sig_allow_across_function_boundary"] = True
    write_gv_yaml(output, payload)
    return True
