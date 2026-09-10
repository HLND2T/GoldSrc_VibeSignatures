#!/usr/bin/env python3
"""Locate engine, the engine module's IEngine* slot (sys_engine.cpp `eng`).

RunListenServer owns the unique TRACEINIT literal "Sys_InitArgv( OrigCmd )"
(official source engine/sys_dll2.cpp). Right after the TraceInit call it
runs eng->SetQuitting(IEngine::QUIT_NOTQUITTING): the first post-TraceInit
load of a writable-data slot whose static value points at the static CEngine
object, followed by a dereference of the loaded pointer, is the `eng` slot
on every validated build (hl-3248..hl-10210 via hw.decrypt.dll, cof-5936,
svencoop-10257; Windows absolute and Linux absolute/PIC encodings alike).
SvEngine Linux is PIC, so the load may be lea reg, [ebx + disp32] with the
ebx GOT anchor recovered from the call-thunk/add-ebx prologue; the emitted
gv_inst_disp then follows the repository's PIC gv convention.

Inlined Sys_InitArgv (hl-10210 hw.so) loads com_argc/com_argv before eng;
those slots hold zero in the static image, so the non-zero-static-pointer
requirement rejects them. Discovery never uses a byte signature or an old
artifact signature; the gv_sig prologue signature is generated only after
the locator validates the current-binary instruction.
"""

from ida_analyze_util import (
    gv_resolution_fields_via_mcp,
    _inspect_function_via_mcp,
    _output_for_symbol,
    parse_mcp_result,
    write_gv_yaml,
)

TARGET_GV_NAME = "engine"
ARGV_STRING = "Sys_InitArgv( OrigCmd )"
TRACEINIT_WINDOW = 6
SCAN_WINDOW = 60
DEREF_WINDOW = 6

LOCATE_PY = r"""
import ida_bytes
import ida_funcs
import ida_idp
import ida_nalt
import ida_segment
import idaapi
import idautils
import idc
import json
import traceback

ARGV_STR = 'Sys_InitArgv( OrigCmd )'
TRACEINIT_WINDOW = 6
SCAN_WINDOW = 60
DEREF_WINDOW = 6

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

def is_mapped(ea):
    return ida_segment.getseg(int(ea)) is not None

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

def functions_for_string(sea):
    starts = []
    for xref in list(idautils.DataRefsTo(int(sea))) + list(idautils.CodeRefsTo(int(sea), 0)):
        func = ida_funcs.get_func(int(xref))
        if func is not None:
            starts.append(int(func.start_ea))
    return sorted(set(starts))

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

def dword_operand_offset(ea, value):
    insn = idautils.DecodeInstruction(int(ea))
    if not insn or insn.size < 4:
        return None
    raw = ida_bytes.get_bytes(int(ea), insn.size) or b''
    target = int(value) & 0xFFFFFFFF
    hits = []
    for off in range(0, insn.size - 3):
        if int.from_bytes(raw[off:off + 4], 'little', signed=False) == target:
            hits.append(off)
    if len(hits) == 1:
        return hits[0]
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

def next_instructions(ea, count):
    out = []
    cur = int(ea)
    for _ in range(count):
        insn = idautils.DecodeInstruction(cur)
        if not insn or insn.size <= 0:
            break
        cur += insn.size
        out.append(cur)
    return out

def derefs_register(ea, reg):
    for cand in next_instructions(ea, DEREF_WINDOW):
        insn = idautils.DecodeInstruction(cand)
        if not insn:
            continue
        mnem = (idc.print_insn_mnem(cand) or '').lower()
        if mnem != 'mov':
            continue
        ops = insn.ops
        if int(ops[0].type) != int(idaapi.o_reg) or int(ops[1].type) == int(idaapi.o_void):
            continue
        if int(ops[1].type) in (int(idaapi.o_displ), int(idaapi.o_phrase)):
            base = reg_name(ops[1])
            if base == reg:
                return True
    return False

def string_reference_site(items, string_ea, ebx_base):
    wanted = int(string_ea)
    for idx, ea in enumerate(items):
        insn = idautils.DecodeInstruction(ea)
        if not insn or insn.size < 4:
            continue
        raw = ida_bytes.get_bytes(ea, insn.size) or b''
        found = False
        for off in range(0, insn.size - 3):
            if int.from_bytes(raw[off:off + 4], 'little', signed=False) == wanted:
                found = True
                break
        if not found and ebx_base is not None:
            info = pic_lea_info(ea, ebx_base)
            if info and info['resolved'] == wanted:
                found = True
        if found:
            return idx
    return None

def main():
    strs = find_exact_strings(ARGV_STR)
    if len(strs) != 1:
        return {'error': 'Sys_InitArgv( OrigCmd ) string count %d' % len(strs)}
    owners = functions_for_string(strs[0])
    if len(owners) != 1:
        return {'error': 'RunListenServer candidates %r' % [hex(x) for x in owners]}
    owner = owners[0]
    fn = ida_funcs.get_func(owner)
    if fn is None:
        return {'error': 'owner is not a function'}
    items = func_items(owner)
    ebx_base = pic_anchor(owner)
    ref_idx = string_reference_site(items, strs[0], ebx_base)
    if ref_idx is None:
        return {'error': 'string reference site not found in owner body'}
    traceinit_ea = None
    for ea in items[ref_idx:min(ref_idx + TRACEINIT_WINDOW, len(items))]:
        if (idc.print_insn_mnem(ea) or '').lower() == 'call':
            traceinit_ea = int(ea)
            break
    if traceinit_ea is None:
        return {'error': 'TraceInit call not found after string reference'}
    start_pos = None
    for idx, ea in enumerate(items):
        if int(ea) > traceinit_ea:
            start_pos = idx
            break
    if start_pos is None:
        return {'error': 'no instructions after TraceInit call'}
    scanned = 0
    for ea in items[start_pos:]:
        if scanned >= SCAN_WINDOW:
            break
        scanned += 1
        insn = idautils.DecodeInstruction(ea)
        if not insn or insn.size < 4:
            continue
        mnem = (idc.print_insn_mnem(ea) or '').lower()
        if mnem != 'mov' and mnem != 'lea':
            continue
        ops = insn.ops
        if int(ops[0].type) != int(idaapi.o_reg):
            continue
        reg = reg_name(ops[0])
        if not reg:
            continue
        slot = None
        operand_off = None
        form = None
        if mnem == 'mov' and int(ops[1].type) == int(idaapi.o_mem):
            addr = int(ops[1].addr)
            if is_writable_data(addr):
                off = dword_operand_offset(ea, addr)
                if off is not None:
                    slot = addr
                    operand_off = off
                    form = 'absolute'
        if slot is None and ebx_base is not None:
            info = pic_lea_info(ea, ebx_base)
            if info and is_writable_data(info['resolved']):
                slot = info['resolved']
                operand_off = info['operand_off']
                form = 'pic'
        if slot is None:
            continue
        value = ida_bytes.get_dword(slot)
        if value == 0 or not is_writable_data(value):
            continue
        if not derefs_register(ea, reg):
            continue
        return {
            'pointer_size': 4,
            'string_ea': hex(strs[0]),
            'owner': hex(owner),
            'owner_end': hex(int(fn.end_ea)),
            'traceinit_ea': hex(traceinit_ea),
            'insn_ea': hex(int(ea)),
            'insn_len': int(insn.size),
            'insn_disp': operand_off,
            'form': form,
            'gv_ea': hex(slot),
            'gv_seg': seg_name(slot),
            'slot_value': hex(value),
            'slot_value_seg': seg_name(value),
            'insn_disasm': disasm(ea),
        }
    return {'error': 'no engine slot load accepted after TraceInit'}

globals().update(locals())
try:
    if idaapi.inf_is_64bit():
        result = json.dumps({'error': 'expected 32-bit x86'})
    else:
        result = json.dumps(main())
except Exception as exc:
    result = json.dumps({'error': str(exc), 'trace': traceback.format_exc()})
"""


async def _locate_engine(session):
    try:
        payload = parse_mcp_result(await session.call_tool("py_eval", {"code": LOCATE_PY}))
    except Exception:  # noqa: BLE001 - MCP failures fail closed.
        return None
    if not isinstance(payload, dict):
        return None
    if payload.get("error") or payload.get("pointer_size") != 4:
        return payload
    required = ("owner", "insn_ea", "insn_len", "insn_disp", "gv_ea")
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
    _ = skill_name, old_yaml_map, new_binary_dir
    if platform not in {"windows", "linux"}:
        return False
    output = _output_for_symbol(expected_outputs, TARGET_GV_NAME)
    if output is None:
        return False
    located = await _locate_engine(session)
    if located is None or located.get("error") or located.get("pointer_size") != 4:
        if debug:
            print(f"  find-{TARGET_GV_NAME}: locator failed {located}")
        return False
    try:
        owner_ea = int(located["owner"], 0)
        insn_ea = int(located["insn_ea"], 0)
        insn_len = int(located["insn_len"])
        insn_disp = int(located["insn_disp"])
        gv_ea = int(located["gv_ea"], 0)
    except (TypeError, ValueError):
        return False
    if gv_ea < int(image_base) or insn_ea < owner_ea:
        return False
    function = await _inspect_function_via_mcp(session, owner_ea, image_base, "RunListenServer")
    if not function or not function.get("func_sig"):
        if debug:
            print(f"  find-{TARGET_GV_NAME}: failed to inspect RunListenServer {located['owner']}")
        return False
    try:
        func_va = int(function["func_va"], 0)
    except (TypeError, ValueError):
        return False
    if func_va != owner_ea:
        return False
    if debug:
        print(
            f"  find-{TARGET_GV_NAME}: owner={located['owner']} slot={located['gv_ea']} "
            f"({located.get('form')}, seg {located.get('gv_seg')}, value {located.get('slot_value')}) "
            f"insn={located['insn_ea']} {located.get('insn_disasm', '')}"
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
