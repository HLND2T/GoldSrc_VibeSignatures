#!/usr/bin/env python3
"""Recover the engine ``host_initialized`` flag from SPR_Shutdown.

engine/cl_draw.c ``SPR_Shutdown`` opens with ``if (!host_initialized) return;``
and clears every sprite global it touches (``gSpriteList``, ``gSpriteCount``,
``gpSprite``, ``ghCrosshair``) before returning, so ``host_initialized`` is the
only writable global the body reads without ever storing to it.
``CGame::AppActivate`` guards both activation branches with the same flag and
shares no other global with SPR_Shutdown, so intersecting the two bodies is an
independent second discriminator. The anchor is the early-out reference itself:
a four-byte read, or the ``lea``/GOT load that materialises the address on PIC
builds, followed by a conditional jump.

Discovery supports PE absolute operands, relocated ELF absolute operands, and
the SvEngine Linux EBX/GOTOFF and GOT-indirect forms. Generated signatures
validate the located output but never participate in discovery.
"""

from ida_analyze_util import parse_mcp_result
from ida_preprocessor_scripts._cgame_appactivate_common import inspect_cgame_appactivate_artifact
from ida_preprocessor_scripts._direct_gv_common import (
    inspect_owner_artifact,
    write_located_globals,
)

TARGET_GLOBAL = "host_initialized"
OWNER_FUNCTION = "SPR_Shutdown"
CROSS_FUNCTION = "CGame_AppActivate"

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
CROSS_EA = CROSS_EA_PLACEHOLDER
JCC_WINDOW = 4
INDEXED_OPERANDS = (int(idaapi.o_displ), int(idaapi.o_phrase))
MEMORY_OPERANDS = (int(idaapi.o_mem), int(idaapi.o_displ), int(idaapi.o_phrase))
DWORD_DTYPE = int(getattr(idaapi, 'dt_dword', 2))
CLOBBERED_BY_CALL = ('eax', 'ecx', 'edx')


def is_mapped(ea):
    return int(ea) != 0 and ida_segment.getseg(int(ea)) is not None


def is_writable_data(ea):
    seg = ida_segment.getseg(int(ea))
    if seg is None or int(ea) == 0:
        return False
    perms = int(getattr(seg, 'perm', 0))
    writable = int(getattr(ida_segment, 'SEGPERM_WRITE', 2))
    executable = int(getattr(ida_segment, 'SEGPERM_EXEC', 1))
    return bool(perms & writable) and not bool(perms & executable)


def is_got(ea):
    seg = ida_segment.getseg(int(ea))
    return seg is not None and ida_segment.get_segm_name(seg) in ('.got', '.got.plt')


def register_name(op):
    # IDA leaves a stale op.reg on absolute operands; only indexed operands
    # carry a real base register.
    if int(op.type) not in INDEXED_OPERANDS:
        return None
    try:
        reg = int(getattr(op, 'reg', -1))
    except Exception:
        return None
    if reg < 0:
        return None
    return (ida_idp.get_reg_name(reg, 4) or '').lower() or None


def destination_register(op):
    if int(op.type) != int(idaapi.o_reg):
        return None
    try:
        reg = int(getattr(op, 'reg', -1))
    except Exception:
        return None
    if reg < 0:
        return None
    return (ida_idp.get_reg_name(reg, 4) or '').lower() or None


def signed32(value):
    value = int(value) & 0xFFFFFFFF
    return value - 0x100000000 if value & 0x80000000 else value


def encoded_displacement(ea, op, insn):
    offb = int(getattr(op, 'offb', 0) or 0)
    raw = ida_bytes.get_bytes(int(ea), int(insn.size)) or b''
    if offb <= 0 or offb + 4 > len(raw):
        return None
    return int.from_bytes(raw[offb:offb + 4], 'little', signed=True)


def pic_anchor(func_start):
    # Recover the SvEngine EBX base from the get-PC thunk; add ebx, imm32.
    ea = int(func_start)
    for _ in range(20):
        insn = idautils.DecodeInstruction(ea)
        if not insn or int(insn.size) <= 0:
            return None
        raw = ida_bytes.get_bytes(ea, int(insn.size)) or b''
        if len(raw) >= 6 and raw[0] == 0x81 and raw[1] == 0xC3:
            imm = int.from_bytes(raw[2:6], 'little', signed=True)
            return (ea + imm) & 0xFFFFFFFF
        ea += int(insn.size)
    return None


def operand_target(ea, op, insn, pic_base, known_bases):
    op_type = int(op.type)
    if op_type == int(idaapi.o_mem):
        value = int(op.addr) & 0xFFFFFFFF
        return (value, False) if is_mapped(value) else (None, False)
    if op_type == int(idaapi.o_imm):
        value = int(op.value) & 0xFFFFFFFF
        return (value, False) if is_mapped(value) else (None, False)
    if op_type not in INDEXED_OPERANDS:
        return (None, False)
    base = register_name(op)
    if base is None or base in ('esp', 'ebp'):
        return (None, False)
    anchor = known_bases.get(base)
    if anchor is None and base == 'ebx' and pic_base is not None:
        anchor = int(pic_base)
    if anchor is None:
        return (None, False)
    if op_type == int(idaapi.o_phrase):
        displacement = 0
    else:
        displacement = encoded_displacement(ea, op, insn)
        if displacement is None:
            displacement = signed32(op.addr)
    value = (int(anchor) + int(displacement)) & 0xFFFFFFFF
    if is_got(value):
        pointee = int(ida_bytes.get_dword(value))
        return (pointee, True) if is_writable_data(pointee) else (None, False)
    return (value, False) if is_mapped(value) else (None, False)


def scan_globals(start):
    pic_base = pic_anchor(int(start))
    known_bases = {}
    records = {}
    order = []
    stores = set()
    for ea in idautils.FuncItems(int(start)):
        insn = idautils.DecodeInstruction(int(ea))
        if not insn:
            continue
        mnem = (idc.print_insn_mnem(int(ea)) or '').lower()
        resolved = []
        for index, op in enumerate(insn.ops):
            if int(op.type) == int(idaapi.o_void):
                break
            target, via_got = operand_target(int(ea), op, insn, pic_base, known_bases)
            if target is None or not is_writable_data(target):
                continue
            resolved.append({
                'index': int(index),
                'target': int(target),
                'via_got': bool(via_got),
                'op_type': int(op.type),
                'dtype': int(getattr(op, 'dtype', -1)),
                'disp': int(getattr(op, 'offb', 0) or 0),
            })
        # Indirect call/jmp operands address IAT/PLT slots, not engine globals.
        if mnem not in ('call', 'jmp'):
            for item in resolved:
                target = item['target']
                if target not in records:
                    records[target] = []
                    order.append(target)
                records[target].append({
                    'ea': int(ea),
                    'mnem': mnem,
                    'length': int(insn.size),
                    'disp': item['disp'],
                    'dtype': item['dtype'],
                    'op_type': item['op_type'],
                    'op_index': item['index'],
                    'via_got': item['via_got'],
                    'disasm': idc.generate_disasm_line(int(ea), 0) or '',
                })
                if mnem == 'mov' and item['index'] == 0 and item['op_type'] in MEMORY_OPERANDS:
                    stores.add(target)
        # Track address-bearing registers only: lea reg, [...], a PIC GOT load,
        # an immediate address, and register-to-register propagation.
        destination = destination_register(insn.ops[0])
        if destination is not None:
            next_base = None
            if mnem == 'lea' and len(resolved) == 1 and resolved[0]['index'] == 1:
                next_base = resolved[0]['target']
            elif mnem == 'mov':
                source = insn.ops[1]
                if int(source.type) == int(idaapi.o_reg):
                    next_base = known_bases.get(destination_register(source))
                elif len(resolved) == 1 and resolved[0]['index'] == 1 and (
                        resolved[0]['via_got'] or int(source.type) == int(idaapi.o_imm)):
                    next_base = resolved[0]['target']
            if next_base is None:
                known_bases.pop(destination, None)
            else:
                known_bases[destination] = int(next_base)
        if mnem == 'call':
            for name in CLOBBERED_BY_CALL:
                known_bases.pop(name, None)
    return {'records': records, 'order': order, 'stores': stores, 'pic_base': pic_base}


def conditional_jump_follows(ea, limit, end_ea):
    insn = idautils.DecodeInstruction(int(ea))
    if not insn:
        return False
    cursor = int(ea) + int(insn.size)
    for _ in range(int(limit)):
        if cursor >= int(end_ea):
            return False
        mnem = (idc.print_insn_mnem(cursor) or '').lower()
        if not mnem or mnem == 'call':
            return False
        if mnem.startswith('j') and mnem != 'jmp':
            return True
        following = idautils.DecodeInstruction(cursor)
        if not following:
            return False
        cursor += int(following.size)
    return False


def encodable_anchor(entries):
    for entry in entries:
        if entry['disp'] > 0 and entry['disp'] + 4 <= entry['length']:
            return entry
    return None


def dword_sized(entry):
    # qboolean host_initialized is a four-byte read; an address materialisation
    # (lea / GOT load) carries the address instead of the value.
    if entry['mnem'] == 'lea' or entry['via_got']:
        return True
    return entry['dtype'] == DWORD_DTYPE


globals().update(locals())

try:
    if idaapi.inf_is_64bit():
        raise RuntimeError('expected 32-bit x86')
    owner = ida_funcs.get_func(int(OWNER_EA))
    cross = ida_funcs.get_func(int(CROSS_EA))
    if owner is None or int(owner.start_ea) != int(OWNER_EA):
        raise RuntimeError('SPR_Shutdown is not a function start')
    if cross is None or int(cross.start_ea) != int(CROSS_EA):
        raise RuntimeError('CGame_AppActivate is not a function start')

    owner_scan = scan_globals(int(OWNER_EA))
    cross_scan = scan_globals(int(CROSS_EA))
    cross_targets = set(cross_scan['order'])
    globals().update(locals())

    read_only = []
    for target in owner_scan['order']:
        if target not in owner_scan['stores']:
            read_only.append(target)

    candidates = []
    rejected = []
    for target in read_only:
        entries = owner_scan['records'][target]
        anchor = encodable_anchor(entries)
        if anchor is None:
            rejected.append({'target': hex(target), 'reason': 'no encodable operand'})
            continue
        if target not in cross_targets:
            rejected.append({'target': hex(target), 'reason': 'absent from CGame_AppActivate'})
            continue
        if not dword_sized(anchor):
            rejected.append({'target': hex(target), 'reason': 'not a four-byte reference'})
            continue
        if not conditional_jump_follows(anchor['ea'], JCC_WINDOW, int(owner.end_ea)):
            rejected.append({'target': hex(target), 'reason': 'no early-out branch'})
            continue
        candidates.append({'target': int(target), 'anchor': anchor})

    if len(candidates) != 1:
        result = json.dumps({
            'error': 'host_initialized candidate is not unique',
            'candidate_count': len(candidates),
            'candidates': [hex(item['target']) for item in candidates],
            'read_only': [hex(target) for target in read_only],
            'stores': [hex(target) for target in sorted(owner_scan['stores'])],
            'cross_targets': [hex(target) for target in sorted(cross_targets)],
            'rejected': rejected,
        })
    else:
        item = candidates[0]
        anchor = item['anchor']
        result = json.dumps({
            'pointer_size': 4,
            'owner_ea': hex(int(OWNER_EA)),
            'cross_ea': hex(int(CROSS_EA)),
            'gv_ea': hex(item['target']),
            'insn_ea': hex(anchor['ea']),
            'insn_len': hex(anchor['length']),
            'insn_disp': hex(anchor['disp']),
            'insn_disasm': anchor['disasm'],
            'read_only': [hex(target) for target in read_only],
            'cross_targets': [hex(target) for target in sorted(cross_targets)],
        })
except Exception as exc:
    result = json.dumps({'error': str(exc), 'trace': traceback.format_exc()})
"""


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
    del old_yaml_map
    if platform not in {"windows", "linux"}:
        return False
    owner = await inspect_owner_artifact(session, new_binary_dir, platform, image_base, OWNER_FUNCTION)
    if owner is None:
        if debug:
            print(f"  {skill_name}: missing or invalid {OWNER_FUNCTION} artifact")
        return False
    cross = await inspect_cgame_appactivate_artifact(session, new_binary_dir, platform, image_base, debug=debug)
    if cross is None:
        if debug:
            print(f"  {skill_name}: missing or invalid {CROSS_FUNCTION} artifact")
        return False
    code = LOCATE_PY.replace("OWNER_EA_PLACEHOLDER", str(owner["owner_ea"])).replace(
        "CROSS_EA_PLACEHOLDER", str(cross["owner_ea"])
    )
    try:
        located = parse_mcp_result(await session.call_tool("py_eval", {"code": code}))
    except Exception:  # noqa: BLE001 - MCP failures fail closed.
        return False
    if not isinstance(located, dict) or located.get("error") or located.get("pointer_size") != 4:
        if debug:
            print(f"  {skill_name}: locator failed {located}")
        return False
    if debug:
        print(
            f"  {skill_name}: gv={located.get('gv_ea')} insn={located.get('insn_ea')} "
            f"{located.get('insn_disasm', '')} cross={located.get('cross_ea')}"
        )
    return await write_located_globals(
        session,
        expected_outputs,
        platform,
        image_base,
        owner,
        {TARGET_GLOBAL: located},
    )
