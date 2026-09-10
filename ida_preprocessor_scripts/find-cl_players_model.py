#!/usr/bin/env python3
"""Locate cl_players_model, &cl.players[0].model in the engine player array.

``cl.players`` is ``player_info_t players[MAX_CLIENTS]`` embedded in
``client_state_t cl`` (engine/client.h). studioapi_SetupPlayerModel gates its
model reload on ``cl.players[playerindex].model[0]`` (engine/r_studio.c), so
the consumed artifact of that function is the anchor.

The locator accepts the unique player-indexed byte test whose index register
carries an element stride solved symbolically from the ``playerindex``
argument (shl/imul/lea chains plus SIB scales): stride 0x24C on WON builds
and 0x250 everywhere else, never the 0x20C DM_PlayerState stride nor the
non-player DM_RemapSkin chains (their index never traces back to the stack
argument). Observed forms: MSVC absolute ``byte_X[reg]`` / ``[reg*4]``
(hl-3248..10210, cof-5936, SvEngine Windows, non-PIC official hw.so), and
SvEngine Linux PIC, where the base register is itself a GOT-anchored
``lea reg, disp32[ebx]`` and the effective address is
``anchor + base_lea_disp + access_disp``.

The emitted gv_va is ``&cl.players[0].model`` — exactly the address the
anchor instruction's displacement (+ GOT base) resolves to, so the artifact
stays self-consistent (gv_inst_disp resolves to gv_va like every other gv
locator). Player ``i``'s model string sits at ``gv_va + i * stride``.
``player_info_t.model`` is at +0x130 in every validated family (leading
fields userid/userinfo[256]/name[32]/spectator/ping/packet_loss never moved;
DWARF-verified on the unstripped hl-8684 and hl-10210 hw.so, where the
struct size is 0x250 and offsetof(players) also cross-checks against
client_state_t); subtract it from gv_va to recover the array head.

Direct-locator exception per the gv policy: the access pattern is
source-defined and was validated on hl-3248..hl-10210, cof-5936, and
svencoop-10257, both platforms where shipped. The gv_sig prologue signature
is generated only after the locator validates the instruction.
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

TARGET_GV_NAME = "cl_players_model"
OWNER_FUNC_NAME = "studioapi_SetupPlayerModel"
MIN_STRIDE = 0x170  # model end (0x170) must fit inside one element
MAX_STRIDE = 0x400
DM_STRIDE = 0x20C

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
MIN_STRIDE = 0x170
MAX_STRIDE = 0x400
DM_STRIDE = 0x20C
BRACKET_TEXT_OPEN = '['

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

def op_text(ea, index):
    try:
        return idc.print_operand(int(ea), index) or ''
    except Exception:
        return ''

def reg_name(op):
    try:
        return (ida_idp.get_reg_name(int(op.reg), 4) or '').lower()
    except Exception:
        return None

def reg32_dest(insn, op):
    if int(op.type) != int(idaapi.o_reg):
        return None
    dtype_size = {0: 1, 1: 2, 2: 4, 3: 4, 4: 8, 5: 16}.get(int(getattr(op, 'dtype', 0)), 0)
    if dtype_size != 4:
        return None
    return reg_name(op)

def bracket_terms(text):
    start = text.find(BRACKET_TEXT_OPEN)
    if start < 0:
        return None
    end = text.find(']', start)
    if end < 0:
        end = len(text)
    terms = []
    for raw in text[start + 1:end].replace(' ', '').split('+'):
        if not raw:
            continue
        piece = raw
        scale = 1
        if '*' in raw:
            base, _, factor = raw.partition('*')
            try:
                scale = int(factor, 0)
            except ValueError:
                return None
            piece = base
        if not piece or piece.endswith('h'):
            continue
        terms.append((piece.lower(), scale))
    return terms

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

def imm_value(insn, index):
    op = insn.ops[index]
    if int(op.type) == int(idaapi.o_imm):
        return int(op.value) & 0xFFFFFFFF
    return None

def main():
    fn = ida_funcs.get_func(SETUP_EA)
    if fn is None or int(fn.start_ea) != SETUP_EA:
        return {'error': 'studioapi_SetupPlayerModel is not a function start'}
    items = func_items(SETUP_EA)
    ebx_base = pic_anchor(SETUP_EA)
    scale = {}
    pic_base_defs = {}
    found = {}
    for index, ea in enumerate(items):
        insn = idautils.DecodeInstruction(int(ea))
        if not insn or not insn.ops:
            continue
        mnem = insn.get_canon_mnem()
        # Candidate model[0] accesses are evaluated with the state that
        # exists before the instruction executes.
        if mnem in ('cmp', 'mov', 'movsx', 'lea'):
            for op_index in range(2):
                if op_index >= len(insn.ops):
                    break
                op = insn.ops[op_index]
                op_type = int(op.type)
                if op_type not in (int(idaapi.o_mem), int(idaapi.o_displ)):
                    continue
                addr = int(op.addr) & 0xFFFFFFFF
                if addr == 0:
                    continue
                if int(getattr(op, 'dtype', 0)) != 0 and mnem != 'lea':
                    continue
                terms = bracket_terms(op_text(ea, op_index))
                if not terms:
                    continue
                regs = [term for term in terms if term[0] in scale]
                if not regs:
                    continue
                stride = 0
                for reg, factor in regs:
                    stride += scale[reg] * factor
                if stride == 0 or stride == DM_STRIDE:
                    continue
                if not (MIN_STRIDE <= stride <= MAX_STRIDE):
                    continue
                tested = False
                if mnem == 'cmp' and len(insn.ops) >= 2 and imm_value(insn, 1) == 0:
                    tested = True
                if not tested:
                    for follow in items[index + 1:index + 3]:
                        if disasm(follow).split() and disasm(follow).split()[0] == 'test':
                            tested = True
                            break
                if not tested:
                    continue
                base_reg = None
                if terms and terms[0][0] not in scale:
                    base_reg = terms[0][0]
                if base_reg is None:
                    model_field = addr
                    form = 'absolute'
                else:
                    base_def = pic_base_defs.get(base_reg)
                    if base_def is None:
                        continue
                    model_field = (base_def['resolved'] + addr) & 0xFFFFFFFF
                    form = 'pic'
                # gv_va is &cl.players[0].model: exactly what the anchor
                # instruction's displacement (+ GOT base) resolves to.
                if not is_writable_data(model_field) or model_field % 4:
                    continue
                disp_off = operand_byte_offset(ea, addr)
                if disp_off is None:
                    continue
                if model_field in found:
                    continue
                found[model_field] = {
                    'insn_ea': int(ea),
                    'insn_len': int(insn.size),
                    'insn_disp': disp_off,
                    'form': form,
                    'stride': stride,
                    'base_reg': base_reg,
                    'gv_ea': model_field,
                    'gv_seg': seg_name(model_field),
                    'insn_disasm': disasm(ea),
                }
        # Sequential scale bookkeeping.
        if mnem == 'call':
            for reg in ('eax', 'ecx', 'edx'):
                scale.pop(reg, None)
        elif insn.ops:
            dest = reg32_dest(insn, insn.ops[0])
            if dest is None:
                continue
            src = insn.ops[1] if len(insn.ops) > 1 else None
            src_type = int(src.type) if src is not None else -1
            if mnem == 'mov':
                if src_type in (int(idaapi.o_displ), int(idaapi.o_phrase)):
                    base = reg_name(src)
                    if base in ('ebp', 'esp'):
                        scale[dest] = 1
                    else:
                        scale.pop(dest, None)
                elif src_type == int(idaapi.o_reg):
                    src_reg = reg32_dest(insn, src)
                    if src_reg is not None and src_reg in scale:
                        scale[dest] = scale[src_reg]
                    else:
                        scale.pop(dest, None)
                else:
                    scale.pop(dest, None)
            elif mnem == 'lea':
                info = pic_lea_info(ea, ebx_base) if ebx_base is not None else None
                if info is not None:
                    pic_base_defs[dest] = {'resolved': info['resolved'], 'ea': int(ea)}
                terms = bracket_terms(op_text(ea, 1))
                total = 0
                ok = bool(terms)
                if terms:
                    for reg, factor in terms:
                        if reg in scale:
                            total += scale[reg] * factor
                        elif reg in ('ebp', 'esp'):
                            continue
                        else:
                            ok = False
                if ok:
                    scale[dest] = total
                else:
                    scale.pop(dest, None)
            elif mnem == 'imul':
                if len(insn.ops) >= 3 and imm_value(insn, 2) is not None:
                    src_reg = reg32_dest(insn, insn.ops[1])
                    imm = imm_value(insn, 2)
                    if src_reg is not None and src_reg in scale:
                        scale[dest] = scale[src_reg] * imm
                    else:
                        scale.pop(dest, None)
                elif src is not None and src_type == int(idaapi.o_imm):
                    if dest in scale:
                        scale[dest] = scale[dest] * int(src.value)
                    else:
                        scale.pop(dest, None)
                elif src is not None and src_type == int(idaapi.o_reg):
                    src_reg = reg32_dest(insn, src)
                    if src_reg is not None and src_reg in scale:
                        scale[dest] = scale[src_reg]
                    else:
                        scale.pop(dest, None)
                else:
                    scale.pop(dest, None)
            elif mnem == 'shl':
                imm = imm_value(insn, 1)
                if imm is not None and imm < 32 and dest in scale:
                    scale[dest] = scale[dest] * (1 << imm)
                else:
                    scale.pop(dest, None)
            elif mnem == 'add':
                src_reg = reg32_dest(insn, src) if src is not None else None
                if src_reg is not None:
                    if src_reg in scale and dest in scale:
                        scale[dest] = scale[dest] + scale[src_reg]
                    elif src_reg in scale:
                        scale[dest] = scale[src_reg]
                    else:
                        scale.pop(dest, None)
                else:
                    scale.pop(dest, None)
            elif mnem in ('sub', 'xor', 'and', 'or', 'pop', 'movsx', 'movzx',
                          'cdq', 'inc', 'dec', 'xchg', 'neg', 'not', 'sar', 'shrd'):
                scale.pop(dest, None)
    if len(found) != 1:
        return {'error': 'cl_players_model candidates: %d' % len(found),
                'candidates': [hex(key) for key in sorted(found)]}
    chosen = next(iter(found.values()))
    return {
        'pointer_size': 4,
        'setup_va': hex(SETUP_EA),
        'pic_anchor': hex(ebx_base) if ebx_base is not None else None,
        'insn_ea': hex(chosen['insn_ea']),
        'insn_len': chosen['insn_len'],
        'insn_disp': chosen['insn_disp'],
        'form': chosen['form'],
        'stride': chosen['stride'],
        'base_reg': chosen['base_reg'],
        'gv_ea': hex(chosen['gv_ea']),
        'gv_seg': chosen['gv_seg'],
        'insn_disasm': chosen['insn_disasm'],
    }

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


async def _locate_cl_players_model(session, setup_ea):
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
    located = await _locate_cl_players_model(session, setup_ea)
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
            f"  find-{TARGET_GV_NAME}: gv={located['gv_ea']} (form {located.get('form')}, "
            f"stride {hex(located.get('stride', 0))}, "
            f"seg {located.get('gv_seg')}) insn={located['insn_ea']} {located.get('insn_disasm', '')}"
        )
    resolution = await gv_resolution_fields_via_mcp(session, insn_ea, insn_disp, gv_ea, image_base, platform)
    if resolution is None:
        return False
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
            **resolution,
        },
    )
    return True
