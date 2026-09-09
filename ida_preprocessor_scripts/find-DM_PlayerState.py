#!/usr/bin/env python3
"""Locate DM_PlayerState, the engine per-client player-model state array.

studioapi_SetupPlayerModel (consumed from its verified artifact) computes
state = &DM_PlayerState[playerindex] with a 0x20C-byte element stride and
then touches state->model at +0x208 (player_model_t: name[0x104],
modelname[0x104], model_t*). The locator collects the base registers of
every [reg+0x208] access in the current IDB body and accepts the first
instruction-ordered writable-data operand whose destination register is
one of them. That survives every observed codegen: direct lea/imul+add
(MSVC hl/cof, SvEngine Windows), stack-slot round-trips (cof debug build),
register recomputation as DM+0x104 (hl-10210 hw.dll picks the earlier base
lea), and SvEngine Linux PIC lea reg, [ebx + disp32] with the ebx GOT
anchor recovered from the call-thunk/add-ebx prologue. The other
0x20C/0x250-strided array in the body (cl.players) never feeds a +0x208
access, and currententity is dereferenced at +0x0B94 instead.

Direct-locator exception per the gv policy: the access pattern is
source-defined, and the chain was validated on hl-3248..hl-10210,
cof-5936, and svencoop-10257, Windows and Linux. The gv_sig prologue
signature is generated only after the locator validates the instruction.
"""

from pathlib import Path

from ida_analyze_util import (
    _inspect_function_via_mcp,
    _load_yaml_mapping,
    _output_for_symbol,
    parse_mcp_result,
    write_gv_yaml,
)

TARGET_GV_NAME = "DM_PlayerState"
OWNER_FUNC_NAME = "studioapi_SetupPlayerModel"
MODEL_FIELD_OFFSET = 0x208

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

SETUP_EA = SETUP_EA_PLACEHOLDER
MODEL_FIELD_OFFSET = 0x208

def is_writable_data(ea):
    seg = ida_segment.getseg(int(ea))
    if seg is None or int(ea) == 0:
        return False
    perms = int(getattr(seg, 'perm', 0))
    executable = int(getattr(ida_segment, 'SEGPERM_EXEC', 4))
    writable = int(getattr(ida_segment, 'SEGPERM_WRITE', 2))
    return bool(perms & writable) and not bool(perms & executable)

def seg_name(ea):
    seg = ida_segment.getseg(int(ea))
    return ida_segment.get_segm_name(seg) if seg else None

def func_items(start):
    fn = ida_funcs.get_func(int(start))
    if fn is None:
        return []
    return [ea for ea in idautils.FuncItems(int(fn.start_ea))]

def disasm(ea):
    return idc.generate_disasm_line(int(ea), 0) or ''

def reg_name(op):
    try:
        return (ida_idp.get_reg_name(int(op.reg), 4) or '').lower()
    except Exception:
        return None

def reg32_name(insn, op):
    if int(op.type) != int(idaapi.o_reg):
        return None
    dtype_size = {0: 1, 1: 2, 2: 4, 3: 4, 4: 8, 5: 16}.get(int(getattr(op, 'dtype', 0)), 0)
    if dtype_size != 4:
        return None
    _ = insn
    return reg_name(op)

def pic_anchor(func_start):
    fn = ida_funcs.get_func(int(func_start))
    if fn is None:
        return None
    ea = int(fn.start_ea)
    for _ in range(10):
        insn = idautils.DecodeInstruction(ea)
        if not insn or insn.size <= 0:
            return None
        raw = ida_bytes.get_bytes(ea, insn.size) or b''
        if raw and len(raw) >= 6 and raw[0] == 0x81 and raw[1] == 0xC3:
            imm = int.from_bytes(raw[2:6], 'little', signed=True) & 0xFFFFFFFF
            return (ea + imm) & 0xFFFFFFFF
        ea += insn.size
    return None

def pic_lea_info(ea, ebx_base):
    insn = idautils.DecodeInstruction(int(ea))
    if not insn or insn.size < 6:
        return None
    raw = ida_bytes.get_bytes(int(ea), insn.size) or b''
    if not raw or raw[0] not in (0x8D, 0x8B):
        return None
    modrm = raw[1]
    mod = modrm >> 6
    rm = modrm & 7
    if mod != 2 or rm not in (3, 4):
        return None
    if raw[0] == 0x8B and ((modrm >> 3) & 7) == 4:
        return None
    if rm == 4:
        if (raw[2] & 7) != 3:
            return None
        off = 3
    else:
        off = 2
    disp = int.from_bytes(raw[off:off + 4], 'little', signed=True)
    return {'operand_off': off, 'resolved': (ebx_base + disp) & 0xFFFFFFFF}

def model_base_registers(items):
    bases = set()
    for ea in items:
        insn = idautils.DecodeInstruction(ea)
        if not insn:
            continue
        for op in insn.ops:
            if int(op.type) == int(idaapi.o_void):
                break
            if int(op.type) in (int(idaapi.o_displ), int(idaapi.o_phrase)):
                try:
                    addr = int(op.addr) & 0xFFFFFFFF
                except Exception:
                    continue
                if addr != MODEL_FIELD_OFFSET:
                    continue
                name = reg_name(op)
                if name:
                    bases.add(name)
    return sorted(bases)

def writable_dword_operands(ea):
    # Structured operand extraction only: a raw byte-window scan matches
    # stray immediates (an `imul reg, reg, 20Ch` window can decode into a
    # mapped .data address) and misattributes them as global references.
    insn = idautils.DecodeInstruction(int(ea))
    if not insn:
        return []
    out = []
    for op in insn.ops:
        op_type = int(op.type)
        if op_type == int(idaapi.o_void):
            break
        value = None
        if op_type == int(idaapi.o_mem):
            value = int(op.addr) & 0xFFFFFFFF
        elif op_type == int(idaapi.o_imm):
            value = int(op.value) & 0xFFFFFFFF
        elif op_type == int(idaapi.o_displ):
            value = int(op.addr) & 0xFFFFFFFF
        if value is not None and is_writable_data(value):
            out.append((0, value))
    return out


def operand_byte_offset(ea, value):
    insn = idautils.DecodeInstruction(int(ea))
    if not insn or insn.size < 4:
        return None
    raw = ida_bytes.get_bytes(int(ea), insn.size) or b''
    target = int(value) & 0xFFFFFFFF
    hits = []
    for off in range(0, insn.size - 3):
        if int.from_bytes(raw[off:off + 4], 'little', signed=False) == target:
            hits.append(off)
    return hits[0] if len(hits) == 1 else None


def is_pointer_slot(value_ea):
    # DM_PlayerState is the array itself, statically zero-filled: its first
    # dword is 0 in the image. A slot whose first dword points into
    # const/code memory is a pointer-to-const slot (e.g. a cvar "developer"
    # name pointer), never the state array.
    seg = ida_segment.getseg(int(value_ea))
    if seg is None:
        return False
    first = ida_bytes.get_dword(int(value_ea))
    if first == 0:
        return False
    seg2 = ida_segment.getseg(first)
    if seg2 is None:
        return False
    perms = int(getattr(seg2, 'perm', 0))
    executable = int(getattr(ida_segment, 'SEGPERM_EXEC', 4))
    writable = int(getattr(ida_segment, 'SEGPERM_WRITE', 2))
    return not bool(perms & writable) or bool(perms & executable)

def main():
    fn = ida_funcs.get_func(SETUP_EA)
    if fn is None or int(fn.start_ea) != SETUP_EA:
        return {'error': 'studioapi_SetupPlayerModel is not a function start'}
    items = func_items(SETUP_EA)
    bases = model_base_registers(items)
    ebx_base = pic_anchor(SETUP_EA)
    # Form B (hl-10210 hw.dll): MSVC folds the model field into an absolute
    # displacement and indexes it directly, so the function carries operands
    # at DM+0x104 and DM+0x208 instead of [reg+0x208] accesses.
    operand_values = set()
    for ea in items:
        for _off, value in writable_dword_operands(ea):
            operand_values.add(value)
        if ebx_base is not None:
            info = pic_lea_info(ea, ebx_base)
            if info and is_writable_data(info['resolved']):
                operand_values.add(info['resolved'])
    for ea in items:
        insn = idautils.DecodeInstruction(ea)
        if not insn or not insn.ops:
            continue
        dest = reg32_name(insn, insn.ops[0])
        info = pic_lea_info(ea, ebx_base) if ebx_base is not None else None
        candidates = []
        if info and is_writable_data(info['resolved']):
            # A PIC instruction's o_displ address is the module-relative
            # displacement, which can land in a writable segment by chance;
            # the GOT-anchored resolution is the only valid interpretation.
            candidates.append({'operand_off': info['operand_off'],
                               'value': info['resolved'], 'form': 'pic'})
        else:
            for _off, value in writable_dword_operands(ea):
                candidates.append({'value': value, 'form': 'absolute'})
        if not candidates:
            continue
        accepted = False
        if bases and dest is not None and dest in bases:
            accepted = True
        else:
            for item in candidates:
                value = item['value']
                if ((value + 0x104) & 0xFFFFFFFF in operand_values
                        and (value + 0x208) & 0xFFFFFFFF in operand_values):
                    accepted = True
                    break
        if not accepted:
            continue
        values = sorted({item['value'] for item in candidates})
        if len(values) != 1:
            return {'error': 'ambiguous data operands at %x: %r' % (ea, [hex(v) for v in values])}
        value = values[0]
        if is_pointer_slot(value):
            continue
        chosen = [item for item in candidates if item['value'] == value][0]
        if chosen['form'] == 'absolute':
            off = operand_byte_offset(ea, value)
            if off is None:
                return {'error': 'operand offset not decodable at %x' % ea}
            chosen['operand_off'] = off
        return {
            'pointer_size': 4,
            'setup_va': hex(SETUP_EA),
            'model_bases': bases,
            'insn_ea': hex(int(ea)),
            'insn_len': int(insn.size),
            'insn_disp': chosen['operand_off'],
            'form': chosen['form'],
            'gv_ea': hex(value),
            'gv_seg': seg_name(value),
            'insn_disasm': disasm(ea),
        }
    return {'error': 'no data operand reaches a model-field access',
            'model_bases': bases}

globals().update(locals())
try:
    if idaapi.inf_is_64bit():
        result = json.dumps({'error': 'expected 32-bit x86'})
    else:
        result = json.dumps(main())
except Exception as exc:
    result = json.dumps({'error': str(exc), 'trace': traceback.format_exc()})
"""


def _owner_artifact(new_binary_dir, platform, func_name, image_base):
    path = Path(new_binary_dir) / f"{func_name}.{platform}.yaml"
    artifact = _load_yaml_mapping(path)
    if not artifact or artifact.get("func_name") != func_name:
        return None
    try:
        value = artifact["func_va"]
        func_ea = int(value, 0) if isinstance(value, str) else int(value)
    except (TypeError, ValueError, KeyError):
        return None
    if func_ea < int(image_base):
        return None
    return artifact, func_ea


async def _locate_dm_player_state(session, setup_ea):
    try:
        code = LOCATE_PY.replace("SETUP_EA_PLACEHOLDER", str(int(setup_ea)))
        payload = parse_mcp_result(await session.call_tool("py_eval", {"code": code}))
    except Exception:  # noqa: BLE001 - MCP failures fail closed.
        return None
    if not isinstance(payload, dict):
        return None
    if payload.get("error") or payload.get("pointer_size") != 4:
        return payload
    required = ("insn_ea", "insn_len", "insn_disp", "gv_ea")
    if any(field not in payload for field in required):
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
    owner = _owner_artifact(new_binary_dir, platform, OWNER_FUNC_NAME, image_base)
    if owner is None:
        if debug:
            print(f"  find-{TARGET_GV_NAME}: missing {OWNER_FUNC_NAME} artifact")
        return False
    owner_data, setup_ea = owner
    located = await _locate_dm_player_state(session, setup_ea)
    if located is None or located.get("error") or located.get("pointer_size") != 4:
        if debug:
            print(f"  find-{TARGET_GV_NAME}: locator failed {located}")
        return False
    try:
        insn_ea = int(located["insn_ea"], 0)
        insn_len = int(located["insn_len"])
        insn_disp = int(located["insn_disp"])
        gv_ea = int(located["gv_ea"], 0)
    except (TypeError, ValueError):
        return False
    if gv_ea < int(image_base) or not (setup_ea <= insn_ea < setup_ea + 0x400):
        return False
    function = await _inspect_function_via_mcp(
        session,
        setup_ea,
        image_base,
        OWNER_FUNC_NAME,
        allow_across_function_boundary=bool(owner_data.get("func_sig_allow_across_function_boundary")),
    )
    if not function or not function.get("func_sig"):
        if debug:
            print(f"  find-{TARGET_GV_NAME}: failed to inspect {OWNER_FUNC_NAME}")
        return False
    try:
        func_va = int(function["func_va"], 0)
    except (TypeError, ValueError):
        return False
    if func_va != setup_ea:
        return False
    if debug:
        print(
            f"  find-{TARGET_GV_NAME}: gv={located['gv_ea']} ({located.get('form')}, "
            f"seg {located.get('gv_seg')}) insn={located['insn_ea']} "
            f"{located.get('insn_disasm', '')} bases={located.get('model_bases')}"
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
