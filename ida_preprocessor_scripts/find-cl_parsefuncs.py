#!/usr/bin/env python3
"""Locate cl_parsefuncs, the client SVC parse-function table.

The table is a static svc_func_t[] in mapped data. Official GoldSrc
(engine/cl_parse.c) starts it with {svc_bad, "svc_bad", NULL} and stores
opcode as a 4-byte slot, then pszname, then pfnParse (12-byte entries).

No x86-32 instruction encodes the table *base*: compilers emit
cl_parsefuncs+4 (pszname) or +8 (pfnParse). LLM found_gv would therefore
select the wrong address. The current-IDB locator is the unique
FULLMATCH "svc_bad" string plus the unique non-executable dword that
points at it and sits at +4 of a validated table prefix.

FULLMATCH "CL_ParseServerMessage: Illegible server message - %s\\n" is
used only to pick the owning function for the gv_sig (function-prologue
style, matching other production GVs). SvEngine Linux is PIC and does
not encode the table VA; fall back to XrefsTo(table+4/+8). Discovery
does not use a byte signature or old YAML.
"""

from ida_analyze_util import (
    _inspect_function_via_mcp,
    _output_for_symbol,
    parse_mcp_result,
    write_gv_yaml,
)

TARGET_GV_NAME = "cl_parsefuncs"

LOCATE_PY = r"""
import ida_bytes
import ida_funcs
import ida_nalt
import ida_segment
import idaapi
import idautils
import idc
import json
import traceback

SVC_BAD = 'svc_bad'
OWNER = 'CL_ParseServerMessage: Illegible server message - %s\n'
ENTRY_SIZE = 12
MAX_TABLE_ENTRIES = 80

def read_cstr(ea, limit=64):
    raw = ida_bytes.get_bytes(int(ea), limit)
    if not raw:
        return None
    end = raw.find(b'\x00')
    if end < 0:
        return None
    try:
        return raw[:end].decode('ascii')
    except UnicodeDecodeError:
        return None

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

def seg_name(ea):
    seg = ida_segment.getseg(int(ea))
    return ida_segment.get_segm_name(seg) if seg else None

def is_exec(ea):
    seg = ida_segment.getseg(int(ea))
    if seg is None:
        return False
    return bool(int(getattr(seg, 'perm', 0)) & int(getattr(ida_segment, 'SEGPERM_EXEC', 4)))

def find_bytes_in_range(needle, start, end, limit=32):
    hits = []
    cursor = int(start)
    end = int(end)
    while cursor < end and len(hits) < limit:
        if not hasattr(ida_bytes, 'find_bytes'):
            break
        ea = ida_bytes.find_bytes(needle, cursor, range_end=end)
        if ea == idaapi.BADADDR:
            break
        hits.append(int(ea))
        cursor = int(ea) + 1
    return hits

def pointer_slots(string_ea):
    needle = int(string_ea).to_bytes(4, 'little', signed=False)
    hits = []
    for seg_ea in idautils.Segments():
        seg = ida_segment.getseg(int(seg_ea))
        if seg is None:
            continue
        if int(getattr(seg, 'perm', 0)) & int(getattr(ida_segment, 'SEGPERM_EXEC', 4)):
            continue
        hits.extend(find_bytes_in_range(needle, int(seg.start_ea), int(seg.end_ea)))
    return hits

def table_from_name_slot(name_slot, string_ea):
    if name_slot < 4 or (name_slot & 3):
        return None
    base = int(name_slot) - 4
    if is_exec(base):
        return None
    opcode0 = ida_bytes.get_dword(base)
    name0 = ida_bytes.get_dword(base + 4)
    pfn0 = ida_bytes.get_dword(base + 8)
    opcode1 = ida_bytes.get_dword(base + 12)
    name1 = ida_bytes.get_dword(base + 16)
    pfn1 = ida_bytes.get_dword(base + 20)
    opcode2 = ida_bytes.get_dword(base + 24)
    name2 = ida_bytes.get_dword(base + 28)
    pfn2 = ida_bytes.get_dword(base + 32)
    opcode3 = ida_bytes.get_dword(base + 36)
    if opcode0 != 0 or name0 != int(string_ea) or pfn0 != 0:
        return None
    if opcode1 != 1 or read_cstr(name1) != 'svc_nop' or pfn1 != 0:
        return None
    if opcode2 != 2 or read_cstr(name2) != 'svc_disconnect' or pfn2 == 0 or not is_exec(pfn2):
        return None
    if opcode3 != 3:
        return None
    count = 0
    ea = base
    terminator = False
    while count < MAX_TABLE_ENTRIES:
        opcode = ida_bytes.get_dword(ea) & 0xFF
        name = ida_bytes.get_dword(ea + 4)
        count += 1
        if opcode == 0xFF:
            terminator = read_cstr(name) == 'End of List'
            break
        ea += ENTRY_SIZE
    if not terminator:
        return None
    return {'table_ea': base, 'entry_count': count}

def functions_for_string(sea):
    starts = []
    for xref in list(idautils.DataRefsTo(int(sea))) + list(idautils.CodeRefsTo(int(sea), 0)):
        func = ida_funcs.get_func(int(xref))
        if func is not None:
            starts.append(int(func.start_ea))
    return sorted(set(starts))

def insn_immediate_off(ea, value):
    insn = idautils.DecodeInstruction(int(ea))
    if not insn or insn.size < 5:
        return None
    raw = ida_bytes.get_bytes(int(ea), insn.size) or b''
    target = int(value) & 0xFFFFFFFF
    for off in range(0, len(raw) - 3):
        if int.from_bytes(raw[off:off + 4], 'little', signed=False) == target:
            return {'insn_ea': int(ea), 'insn_len': int(insn.size), 'insn_disp': int(off)}
    return None

def find_access(func_start, func_end, values):
    preferred = []
    fallback = []
    ea = int(func_start)
    end = int(func_end)
    wanted_plus4 = int(values[0])
    wanted = {int(v) & 0xFFFFFFFF for v in values}
    while ea < end:
        flags = ida_bytes.get_full_flags(ea)
        if ida_bytes.is_code(flags) and ida_bytes.is_head(flags):
            for value in wanted:
                match = insn_immediate_off(ea, value)
                if match:
                    (preferred if value == wanted_plus4 else fallback).append(match)
                    break
        next_ea = ida_bytes.next_head(ea, end)
        if next_ea == idaapi.BADADDR or next_ea <= ea:
            break
        ea = int(next_ea)
    if preferred:
        return preferred[0]
    if fallback:
        return fallback[0]
    return None

def find_access_anywhere(values):
    for value in values:
        needle = int(value).to_bytes(4, 'little', signed=False)
        for seg_ea in idautils.Segments():
            seg = ida_segment.getseg(int(seg_ea))
            if seg is None or not (int(getattr(seg, 'perm', 0)) & int(getattr(ida_segment, 'SEGPERM_EXEC', 4))):
                continue
            for hit in find_bytes_in_range(needle, int(seg.start_ea), int(seg.end_ea), limit=64):
                head = int(ida_bytes.get_item_head(hit))
                match = insn_immediate_off(head, value)
                if match:
                    func = ida_funcs.get_func(head)
                    if func is not None:
                        match['func_start'] = int(func.start_ea)
                        return match
    return None

def first_disp_off(ea):
    insn = idautils.DecodeInstruction(int(ea))
    if not insn:
        return None
    for op in insn.ops:
        if int(op.type) == int(idaapi.o_void):
            continue
        off = int(getattr(op, 'offb', 0))
        if off > 0 and off + 4 <= insn.size:
            return {'insn_ea': int(ea), 'insn_len': int(insn.size), 'insn_disp': off}
    return None

def access_from_xrefs(targets, preferred_func):
    matches = []
    for target in targets:
        for xref in idautils.XrefsTo(int(target)):
            frm = int(xref.frm)
            if not is_exec(frm):
                continue
            func = ida_funcs.get_func(frm)
            if func is None:
                continue
            match = insn_immediate_off(frm, target) or first_disp_off(frm)
            if not match:
                continue
            match['func_start'] = int(func.start_ea)
            matches.append(match)
    if preferred_func is not None:
        owned = [item for item in matches if item['func_start'] == int(preferred_func)]
        if owned:
            return owned[0]
    return matches[0] if matches else None

globals().update(locals())

try:
    if idaapi.inf_is_64bit():
        raise RuntimeError('expected 32-bit x86')
    svc_bad = find_exact_strings(SVC_BAD)
    if len(svc_bad) != 1:
        result = json.dumps({'error': 'svc_bad string is not unique', 'string_count': len(svc_bad)})
    else:
        string_ea = svc_bad[0]
        tables = []
        for slot in pointer_slots(string_ea):
            cand = table_from_name_slot(slot, string_ea)
            if cand:
                tables.append(cand)
        unique = []
        seen = set()
        for table in tables:
            if table['table_ea'] not in seen:
                seen.add(table['table_ea'])
                unique.append(table)
        owner_hits = find_exact_strings(OWNER)
        owners = []
        for sea in owner_hits:
            owners.extend(functions_for_string(sea))
        owners = sorted(set(owners))
        if len(unique) != 1:
            result = json.dumps({
                'error': 'cl_parsefuncs table is not unique',
                'string_ea': hex(string_ea),
                'table_count': len(unique),
                'tables': [hex(item['table_ea']) for item in unique],
            })
        else:
            table_ea = unique[0]['table_ea']
            plus4 = table_ea + 4
            plus8 = table_ea + 8
            access = None
            owner_ea = owners[0] if len(owners) == 1 else None
            if owner_ea is not None:
                func = ida_funcs.get_func(owner_ea)
                if func is not None:
                    access = find_access(int(func.start_ea), int(func.end_ea), (plus4, plus8))
                    if access:
                        access['func_start'] = owner_ea
            if access is None:
                access = find_access_anywhere((plus4, plus8))
            if access is None:
                access = access_from_xrefs((plus4, plus8), owner_ea)
            if access is None or 'func_start' not in access:
                result = json.dumps({
                    'error': 'no instruction encodes cl_parsefuncs+4 or +8',
                    'string_ea': hex(string_ea),
                    'table_ea': hex(table_ea),
                    'owner_count': len(owners),
                    'owners': [hex(ea) for ea in owners],
                })
            else:
                result = json.dumps({
                    'pointer_size': 4,
                    'string_ea': hex(string_ea),
                    'string_count': 1,
                    'table_ea': hex(table_ea),
                    'entry_count': unique[0]['entry_count'],
                    'table_seg': seg_name(table_ea),
                    'owner_count': len(owners),
                    'owner_ea': hex(access['func_start']),
                    'insn_ea': hex(access['insn_ea']),
                    'insn_len': access['insn_len'],
                    'insn_disp': access['insn_disp'],
                    'insn_disasm': idc.generate_disasm_line(access['insn_ea'], 0) or '',
                })
except Exception as exc:
    result = json.dumps({'error': str(exc), 'trace': traceback.format_exc()})
"""


async def _locate_cl_parsefuncs(session):
    try:
        payload = parse_mcp_result(await session.call_tool("py_eval", {"code": LOCATE_PY}))
    except Exception:  # noqa: BLE001 - MCP failures fail closed.
        return None
    if not isinstance(payload, dict):
        return None
    if payload.get("error") or payload.get("pointer_size") != 4:
        return payload if isinstance(payload, dict) else None
    if int(payload.get("string_count") or 0) != 1:
        return payload
    required = ("table_ea", "owner_ea", "insn_ea", "insn_len", "insn_disp")
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
    located = await _locate_cl_parsefuncs(session)
    if located is None or located.get("error") or located.get("pointer_size") != 4:
        if debug:
            print(f"  find-cl_parsefuncs: locator failed {located}")
        return False
    try:
        table_ea = int(located["table_ea"], 0)
        owner_ea = int(located["owner_ea"], 0)
        insn_ea = int(located["insn_ea"], 0)
        insn_len = int(located["insn_len"])
        insn_disp = int(located["insn_disp"])
    except (TypeError, ValueError):
        return False
    if table_ea < int(image_base) or insn_ea < owner_ea:
        return False
    function = await _inspect_function_via_mcp(session, owner_ea, image_base, "CL_ParseServerMessage")
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
            f"  find-cl_parsefuncs: table={located['table_ea']} "
            f"seg={located.get('table_seg')} entries={located.get('entry_count')} "
            f"owner={located['owner_ea']} insn={located['insn_ea']} "
            f"{located.get('insn_disasm', '')}"
        )
    write_gv_yaml(
        output,
        {
            "gv_name": TARGET_GV_NAME,
            "gv_va": hex(table_ea),
            "gv_rva": hex(table_ea - int(image_base)),
            "gv_sig": function["func_sig"],
            "gv_sig_va": function["func_va"],
            "gv_inst_offset": hex(insn_ea - func_va),
            "gv_inst_length": hex(insn_len),
            "gv_inst_disp": hex(insn_disp),
        },
    )
    return True
