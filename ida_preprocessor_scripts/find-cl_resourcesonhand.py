#!/usr/bin/env python3
"""Locate the client on-hand resource list sentinel from CL_PrecacheResources.

The sentinel is ``&cl.resourcesonhand`` (member at +4 of the engine global
``client_state_t cl``). ``CL_PrecacheResources`` walks that circular list:
``pResource = cl.resourcesonhand.pNext`` loads through ``[sentinel+0x80]``
(the engine-private ``resource_s::pNext`` offset) and the loop condition
compares ``pResource != &cl.resourcesonhand``. This direct locator pairs the
sentinel's compare/address reference with the ``+0x80`` load inside the
already-covered ``CL_PrecacheResources`` function, so it avoids an
unnecessary LLM dependency while preserving the verified function signature
as the runtime anchor.

Cross-version evidence (validated 2026-09-06):
- hl-10210 hw.dll 0x101A44C0: ``cmp esi, offset 0x11257F64`` + ``mov esi, [0x11257FE4]``
- hl-10210 hw.so  0x136BE0:  ``cmp eax, 0xC2FA84`` + ``mov ebx, [0xC2FB04]``
- svencoop-10257 hw.dll 0x1D26540: ``cmp esi, offset 0x21092D4`` + ``mov esi, [0x2109354]``
- svencoop-10257 hw.so  0x113350: PIC GOTOFF ``lea ecx, [ebx+sentinel-GOT]`` +
  ``cmp esi, ecx`` + ``mov esi, [ebx+sentinel+0x80-GOT]``
- cof-5936 hw.dll 0x1D2FFB6: ``cmp [ebp+var], offset 0x2DD5A84`` + ``mov eax, [0x2DD5B04]``

The compare operand alternates between register-immediate, stack-memory-
immediate, and PIC register forms, so candidates are collected from IDA data
cross-references (which resolve GOTOFF forms to absolute targets) rather than
from one fixed instruction encoding.
"""

from pathlib import Path

from ida_analyze_util import (
    gv_resolution_fields_via_mcp,
    _inspect_function_via_mcp,
    _load_yaml_mapping,
    _output_for_symbol,
    parse_mcp_result,
    write_gv_yaml,
)


TARGET_GV_NAME = "cl_resourcesonhand"
OWNER_FUNC_NAME = "CL_PrecacheResources"
PNEXT_OFFSET = 0x80
LEA_CMP_WINDOW = 6


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
PNEXT_OFFSET = PNEXT_OFFSET_PLACEHOLDER
LEA_CMP_WINDOW = LEA_CMP_WINDOW_PLACEHOLDER


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


def memory_operand(op):
    return int(op.type) in (int(idaapi.o_mem), int(idaapi.o_displ), int(idaapi.o_phrase))


def absolute_targets(entry):
    # Operand-level absolutes (o_imm value / o_mem addr) survive IDB-structured
    # references that normalize DataRefsFrom onto the owning struct base; the
    # DataRefsFrom union covers PIC GOTOFF forms whose o_displ carries only a
    # GOT-relative displacement. Stack-relative o_displ operands contribute
    # nothing here because neither channel resolves them to an absolute.
    targets = set()
    insn = entry['insn']
    for op in insn.ops:
        if int(op.type) == int(idaapi.o_void):
            break
        if int(op.type) == int(idaapi.o_imm):
            value = int(op.value) & 0xFFFFFFFF
            if value:
                targets.add(value)
        elif int(op.type) == int(idaapi.o_mem):
            targets.add(int(op.addr) & 0xFFFFFFFF)
    targets.update(entry['refs'])
    return targets


globals().update(locals())

try:
    if idaapi.inf_is_64bit():
        raise RuntimeError('expected 32-bit x86')
    owner = ida_funcs.get_func(int(OWNER_EA))
    if owner is None or int(owner.start_ea) != int(OWNER_EA):
        raise RuntimeError('CL_PrecacheResources is not a function start')

    instructions = []
    for item_ea in idautils.FuncItems(int(owner.start_ea)):
        item_ea = int(item_ea)
        insn = idautils.DecodeInstruction(item_ea)
        if not insn:
            continue
        instructions.append({
            'ea': item_ea,
            'insn': insn,
            'mnem': (idc.print_insn_mnem(item_ea) or '').lower(),
            'refs': sorted(int(ref) for ref in idautils.DataRefsFrom(item_ea)),
        })

    loads = {}
    for entry in instructions:
        insn = entry['insn']
        if entry['mnem'] != 'mov':
            continue
        if len(insn.ops) < 2 or register_id(insn.ops[0]) is None or not memory_operand(insn.ops[1]):
            continue
        for target in absolute_targets(entry):
            if target not in loads:
                loads[target] = entry['ea']

    cmp_refs = {}
    lea_refs = {}
    for index, entry in enumerate(instructions):
        insn = entry['insn']
        if entry['mnem'] == 'cmp':
            for target in absolute_targets(entry):
                if writable_data_segment(target):
                    cmp_refs.setdefault(target, entry['ea'])
        elif entry['mnem'] == 'lea':
            if len(insn.ops) < 2:
                continue
            target_reg = register_id(insn.ops[0])
            if target_reg is None:
                continue
            matched = False
            for target in absolute_targets(entry):
                if not writable_data_segment(target):
                    continue
                for follower in instructions[index + 1:index + 1 + int(LEA_CMP_WINDOW)]:
                    if follower['mnem'] != 'cmp':
                        continue
                    follower_insn = follower['insn']
                    operand_regs = [register_id(follower_insn.ops[i]) for i in range(2)]
                    if target_reg in operand_regs:
                        lea_refs.setdefault(target, entry['ea'])
                        matched = True
                        break
                if matched:
                    break

    candidates = []
    for value in sorted(set(cmp_refs) | set(lea_refs)):
        load_ea = loads.get(value + int(PNEXT_OFFSET))
        if load_ea is None:
            continue
        ref_ea = cmp_refs.get(value, lea_refs.get(value))
        candidates.append({
            'gv_ea': value,
            'ref_ea': int(ref_ea),
            'load_ea': int(load_ea),
            'source': 'cmp' if value in cmp_refs else 'lea',
        })

    if len(candidates) != 1:
        result = json.dumps({
            'error': 'sentinel candidates are not unique',
            'owner_ea': hex(int(owner.start_ea)),
            'candidate_count': len(candidates),
            'candidates': [
                {
                    'gv_ea': hex(c['gv_ea']),
                    'ref_ea': hex(c['ref_ea']),
                    'load_ea': hex(c['load_ea']),
                    'source': c['source'],
                }
                for c in candidates
            ],
        })
    else:
        candidate = candidates[0]
        ref_ea = candidate['ref_ea']
        ref_insn = idautils.DecodeInstruction(ref_ea)
        disp = 0
        for op in ref_insn.ops:
            if int(op.type) == int(idaapi.o_void):
                break
            if int(op.type) == int(idaapi.o_imm) and (int(op.value) & 0xFFFFFFFF) == int(candidate['gv_ea']):
                disp = int(getattr(op, 'offb', 0))
                break
        if not disp:
            for op in ref_insn.ops:
                if int(op.type) == int(idaapi.o_void):
                    break
                if int(op.type) == int(idaapi.o_displ) and int(op.addr) and int(getattr(op, 'offb', 0)):
                    disp = int(op.offb)
                    break
        result = json.dumps({
            'pointer_size': 4,
            'owner_ea': hex(int(owner.start_ea)),
            'gv_ea': candidate['gv_ea'],
            'gv_seg': seg_name(candidate['gv_ea']),
            'insn_ea': ref_ea,
            'insn_len': int(ref_insn.size),
            'insn_disp': disp,
            'insn_disasm': idc.generate_disasm_line(ref_ea, 0) or '',
            'load_ea': candidate['load_ea'],
            'load_disasm': idc.generate_disasm_line(candidate['load_ea'], 0) or '',
            'source': candidate['source'],
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


async def _locate_sentinel(session, owner_ea):
    code = (
        LOCATE_PY.replace("OWNER_EA_PLACEHOLDER", str(int(owner_ea)))
        .replace("PNEXT_OFFSET_PLACEHOLDER", str(PNEXT_OFFSET))
        .replace("LEA_CMP_WINDOW_PLACEHOLDER", str(LEA_CMP_WINDOW))
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
            print("  find-cl_resourcesonhand: missing output or owner artifact")
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
    located = await _locate_sentinel(session, owner_ea)
    if located is None or located.get("error") or located.get("pointer_size") != 4:
        if debug:
            print(f"  find-cl_resourcesonhand: direct locator failed {located}")
        return False
    try:
        located_owner_ea = int(located["owner_ea"], 0)
        owner_end_ea = owner_ea + int(owner_function["func_size"], 0)
        gv_ea = int(located["gv_ea"])
        insn_ea = int(located["insn_ea"])
        insn_len = int(located["insn_len"])
        insn_disp = int(located["insn_disp"])
    except (KeyError, TypeError, ValueError):
        return False
    if located_owner_ea != owner_ea or gv_ea < int(image_base) or insn_ea < owner_ea:
        return False
    if not owner_ea <= insn_ea and insn_ea + insn_len <= owner_end_ea:
        return False
    resolution = await gv_resolution_fields_via_mcp(session, insn_ea, insn_disp, gv_ea, image_base, platform)
    if resolution is None:
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
        **resolution,
    }
    if allow_across:
        payload["gv_sig_allow_across_function_boundary"] = True
    if debug:
        print(
            f"  find-cl_resourcesonhand: {TARGET_GV_NAME}={located['gv_ea']} "
            f"seg={located.get('gv_seg')} insn={located['insn_ea']} {located.get('insn_disasm', '')}"
        )
    write_gv_yaml(output, payload)
    return True
