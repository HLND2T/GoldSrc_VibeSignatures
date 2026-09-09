"""Shared locator for studioapi_SetupPlayerModel across engine families.

Anchor chain (validated on hl-3248..hl-10210, cof-5936, svencoop-10257; both
platforms where shipped):

1. The engine's ClientDLL_CheckStudioInterface diagnostic literal is unique.
   GoldSrc/HL25/CoF use one wording, SvEngine another, so each family ships
   its own finder script that only differs in this string.
2. Every function owning that literal passes &engine_studio_api to the
   client's HUD_GetStudioModelInterface. On Windows and non-PIC Linux the
   table VA appears as an absolute dword operand; SvEngine Linux is PIC and
   encodes it as lea reg, [ebx + disp32] with the ebx GOT anchor recovered
   from the call-thunk/add-ebx prologue. Linux builds may have two string
   owners (DWARF names only one ClientDLL_CheckStudioInterface); both
   reference the same table, so the locator collapses on the unique table
   VA instead of the owner.
3. engine_studio_api_t (common/r_studioint.h) stores studioapi_SetupPlayerModel
   at fixed slot 0x7C. The table is validated as a writable-data run of
   non-zero code pointers before the slot is read.
4. The slot function must reference "models/player/%s/%s.mdl", which only
   studioapi_SetupPlayerModel and R_StudioDrawPlayer do.

Discovery never uses a byte signature or a prior artifact signature.
"""

from ida_analyze_util import (
    _inspect_function_via_mcp,
    _output_for_symbol,
    parse_mcp_result,
    write_func_yaml,
)

HL_STUDIO_STRING = "Couldn't get client .dll studio model rendering interface.  Version mismatch?\n"
SVC_STUDIO_STRING = "Couldn't get client library studio model rendering interface. Version mismatch?\n"
PLAYER_FMT_STRING = "models/player/%s/%s.mdl"
SETUP_SLOT_OFFSET = 0x7C
TABLE_DWORDS = 45
MIN_TABLE_CODE_RUN = 43

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

STUDIO_STR = STUDIO_STR_PLACEHOLDER
FMT_STR = 'models/player/%s/%s.mdl'
SETUP_SLOT_OFF = 0x7C
TABLE_DWORDS = 45
MIN_TABLE_CODE_RUN = 43

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

def is_exec(ea):
    seg = ida_segment.getseg(int(ea))
    if seg is None or int(ea) == 0:
        return False
    return bool(int(getattr(seg, 'perm', 0)) & int(getattr(ida_segment, 'SEGPERM_EXEC', 4)))

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

def validate_table(cand):
    if not is_writable_data(cand):
        return None
    run = 0
    for i in range(TABLE_DWORDS):
        value = ida_bytes.get_dword(int(cand) + i * 4)
        if value != 0 and is_exec(value):
            run += 1
    if run < MIN_TABLE_CODE_RUN:
        return None
    slot = ida_bytes.get_dword(int(cand) + SETUP_SLOT_OFF)
    fn = ida_funcs.get_func(slot) if slot else None
    if fn is None or int(fn.start_ea) != slot:
        return None
    return {'table_ea': int(cand), 'table_seg': seg_name(cand),
            'code_run': run, 'setup_slot': slot}

def absolute_data_operands(ea):
    insn = idautils.DecodeInstruction(int(ea))
    if not insn or insn.size < 4:
        return []
    raw = ida_bytes.get_bytes(int(ea), insn.size) or b''
    out = []
    for off in range(0, insn.size - 3):
        value = int.from_bytes(raw[off:off + 4], 'little', signed=False)
        if is_mapped(value) and is_writable_data(value):
            out.append((off, value))
    return out

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

def pic_ebx_displacements(func_start, ebx_base):
    out = []
    for ea in func_items(func_start):
        insn = idautils.DecodeInstruction(ea)
        if not insn or insn.size < 6:
            continue
        raw = ida_bytes.get_bytes(ea, insn.size) or b''
        if raw[0] not in (0x8D, 0x8B):
            continue
        modrm = raw[1]
        mod = modrm >> 6
        rm = modrm & 7
        if mod != 2 or rm not in (3, 4):
            continue
        if raw[0] == 0x8B and ((modrm >> 3) & 7) == 4:
            continue
        if rm == 4:
            sib = raw[2]
            if (sib & 7) != 3:
                continue
            disp = int.from_bytes(raw[3:7], 'little', signed=True)
            off = 3
        else:
            disp = int.from_bytes(raw[2:6], 'little', signed=True)
            off = 2
        out.append({'ea': int(ea), 'insn_len': int(insn.size), 'operand_off': off,
                    'resolved': (ebx_base + disp) & 0xFFFFFFFF,
                    'disasm': disasm(ea)})
    return out

def pic_target_of(raw, base):
    if not raw or len(raw) < 6 or raw[0] not in (0x8D, 0x8B):
        return None
    modrm = raw[1]
    mod = modrm >> 6
    rm = modrm & 7
    if mod != 2 or rm not in (3, 4):
        return None
    if raw[0] == 0x8B and ((modrm >> 3) & 7) == 4:
        return None
    if rm == 4:
        sib = raw[2]
        if (sib & 7) != 3:
            return None
        disp = int.from_bytes(raw[3:7], 'little', signed=True)
    else:
        disp = int.from_bytes(raw[2:6], 'little', signed=True)
    return (base + disp) & 0xFFFFFFFF

def references_string(func_start, string_eas):
    wanted = set(int(x) for x in string_eas)
    if not wanted:
        return False
    base = pic_anchor(func_start)
    for ea in func_items(func_start):
        insn = idautils.DecodeInstruction(ea)
        if not insn or insn.size < 4:
            continue
        raw = ida_bytes.get_bytes(ea, insn.size) or b''
        for off in range(0, insn.size - 3):
            value = int.from_bytes(raw[off:off + 4], 'little', signed=False)
            if value in wanted:
                return True
        if base is not None:
            target = pic_target_of(raw, base)
            if target is not None and target in wanted:
                return True
    return False

def main():
    strs = find_exact_strings(STUDIO_STR)
    if len(strs) != 1:
        return {'error': 'studio interface string count %d' % len(strs)}
    owners = functions_for_string(strs[0])
    if not owners:
        return {'error': 'studio interface string has no owning function'}
    tables = {}
    for own in owners:
        for ea in func_items(own):
            for off, value in absolute_data_operands(ea):
                info = validate_table(value)
                if info and value not in tables:
                    info['form'] = 'absolute'
                    info['table_insn'] = '%x: %s' % (ea, disasm(ea))
                    tables[value] = info
        base = pic_anchor(own)
        if base:
            for item in pic_ebx_displacements(own, base):
                info = validate_table(item['resolved'])
                if info and item['resolved'] not in tables:
                    info['form'] = 'pic'
                    info['table_insn'] = item['disasm']
                    tables[item['resolved']] = info
    if len(tables) != 1:
        return {'error': 'engine_studio_api table candidates: %d' % len(tables),
                'tables': [hex(t) for t in sorted(tables)]}
    table_ea, info = next(iter(tables.items()))
    setup_va = info['setup_slot']
    fmts = find_exact_strings(FMT_STR)
    if not fmts:
        return {'error': 'player model format string missing', 'table_ea': hex(table_ea)}
    if not references_string(setup_va, fmts):
        return {'error': 'slot 0x7C function does not reference the player model format',
                'table_ea': hex(table_ea), 'setup_slot': hex(setup_va)}
    fn = ida_funcs.get_func(setup_va)
    return {
        'pointer_size': 4,
        'string_ea': hex(strs[0]),
        'owners': [hex(x) for x in owners],
        'table_ea': hex(table_ea),
        'table_seg': info['table_seg'],
        'table_form': info['form'],
        'table_insn': info['table_insn'],
        'code_run': info['code_run'],
        'setup_va': hex(setup_va),
        'setup_end': hex(int(fn.end_ea)) if fn else None,
        'fmt_count': len(fmts),
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


async def locate_setup_player_model(session, studio_string):
    try:
        code = LOCATE_PY.replace("STUDIO_STR_PLACEHOLDER", repr(studio_string))
        payload = parse_mcp_result(await session.call_tool("py_eval", {"code": code}))
    except Exception:  # noqa: BLE001 - MCP failures fail closed.
        return None
    if not isinstance(payload, dict):
        return None
    if payload.get("error") or payload.get("pointer_size") != 4:
        return payload
    required = ("table_ea", "setup_va")
    if any(field not in payload for field in required):
        return None
    return payload


async def preprocess_studio_setup_player_model(
    session,
    expected_outputs,
    platform,
    image_base,
    *,
    target_name,
    studio_string,
    debug=False,
):
    if platform not in {"windows", "linux"}:
        return False
    output = _output_for_symbol(expected_outputs, target_name)
    if output is None:
        return False
    located = await locate_setup_player_model(session, studio_string)
    if located is None or located.get("error") or located.get("pointer_size") != 4:
        if debug:
            print(f"  {target_name}: locator failed {located}")
        return False
    try:
        table_ea = int(located["table_ea"], 0)
        setup_ea = int(located["setup_va"], 0)
    except (TypeError, ValueError):
        return False
    if table_ea < int(image_base) or setup_ea < int(image_base):
        return False
    function = await _inspect_function_via_mcp(session, setup_ea, image_base, target_name)
    allow_across = False
    if not function or not function.get("func_sig"):
        # PIC prologues (SvEngine Linux) can be almost fully wildcarded within
        # the default 64-token window; the across-boundary window still starts
        # at the same entry and only grows the validated extent.
        function = await _inspect_function_via_mcp(
            session, setup_ea, image_base, target_name, allow_across_function_boundary=True
        )
        allow_across = function is not None and bool(function.get("func_sig"))
    if not function or not function.get("func_sig"):
        if debug:
            print(f"  {target_name}: failed to inspect slot function {located['setup_va']}")
        return False
    try:
        func_va = int(function["func_va"], 0)
    except (TypeError, ValueError):
        return False
    if func_va != setup_ea:
        return False
    if debug:
        print(
            f"  {target_name}: table={located['table_ea']} ({located.get('table_form')}, "
            f"seg {located.get('table_seg')}, code_run {located.get('code_run')}) "
            f"setup={located['setup_va']} owners={located.get('owners')}"
        )
    payload = {
        "func_name": target_name,
        "func_va": function["func_va"],
        "func_rva": function["func_rva"],
        "func_size": function["func_size"],
        "func_sig": function["func_sig"],
    }
    if allow_across:
        payload["func_sig_allow_across_function_boundary"] = True
    write_func_yaml(output, payload)
    return True
