"""Shared locators for the studio player-model family across engine families.

Anchor chains (validated on hl-3248..hl-10210, cof-5936, svencoop-10257; both
platforms where shipped):

studioapi_SetupPlayerModel:

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

R_StudioDrawPlayer:

1. The same ClientDLL_CheckStudioInterface diagnostic anchors the owner, and
   the same operand scan now keeps the &pStudioAPI argument.
2. pStudioAPI's static initializer is the r_studio_interface_t studio object
   {STUDIO_INTERFACE_VERSION, R_StudioDrawModel, R_StudioDrawPlayer}, so a
   candidate validates only when its image dword points at writable data
   whose first dword is 1 and whose +4/+8 slots are executable function
   starts. &engine_studio_api (first member is a code pointer) and
   &cl_funcs fields (zero in the image) never qualify.
3. The interface entry is studio+8. GCC Linux builds move the
   "models/player/%s/%s.mdl" Q_snprintf into an R_StudioDrawPlayer.part.N
   cold clone that the entry only tail-jumps to, so the semantic check
   accepts the format string on the entry or any direct call/jmp target,
   and the remaining format-string owner must equal the verified
   studioapi_SetupPlayerModel artifact (DAG input).

studioapi slot accessors (GetCurrentEntity 0x18, StudioSetHeader 0x8C,
SetRenderModel 0x90, SetChromeOrigin 0x9C) and their engine globals:

1. The same diagnostic anchors the owner and the unique engine_studio_api
   table (>= 43 code-pointer dwords; SvEngine ships 47/48 ABI-compatible
   entries), then the fixed ABI slot names the accessor.
2. The accessor body owns the global access, recovered through IDA operand
   data references (which resolve absolute, SSE movss, x87 fld/fstp, and
   GOTOFF [reg+disp32] forms to their true targets). Only instructions with
   a real 4-byte displacement operand contribute refs, so pointer-chasing
   loads ([reg] without disp32) and stack operands never pollute the shape.
   Observed shapes: GetCurrentEntity reads exactly one global
   (currententity), StudioSetHeader/SetRenderModel store exactly one global
   (pstudiohdr/r_model), SetChromeOrigin reads one 12-byte cluster
   (r_origin) and writes another (g_ChromeOrigin); SvEngine Linux accesses
   the globals through an eax-anchored GOTOFF prologue. SvEngine Linux GV
   artifacts additionally emit gv_pic_addend: register-relative disp32
   sites embed var-GOT (no relocation; e.g. r_model disp 0xA388D4 + GOT RVA
   0x2EE000 = declared 0xD268D4), so the runtime decoder must add the GOT
   RVA to the embedded dword. Absolute-form sites (all other binaries) keep
   the plain *(u32*) decode because their embedded dword is either the
   link-time address (R_386_RELATIVE) or loader-filled from the symbol
   (R_386_32), both yielding the true runtime address.
3. Direct-locator exception (find-cl_resourcesonhand precedent): the gv
   artifacts use the owner accessor's func_sig with gv_inst_offset/disp
   pointing at the first base-referencing instruction. Cross-version
   evidence (2026-09-10 probes, both platforms where shipped):
   hl-10210 hw.dll currententity 0x10DC5618 / pstudiohdr 0x104D1BF8 /
   r_model 0x104EA08C / r_origin 0x10DC5578 / g_ChromeOrigin 0x104EA0A0;
   hl-10210 hw.so 0xF7D930 / 0x3378C0 / 0x320FD4; hl-8684 hw.dll
   0x2BC98FC / 0x23B64E0 / 0x235AA58 / 0x2BC98F0 / 0x2358840; hl-3248
   0x2C2023C / 0x24849C0 / 0x2435490 / 0x2C20230 / 0x2433278; svencoop-10257
   hw.dll 0x3F94150 / 0x8DDD290 / 0x8DF3B24 / 0x3F941D8 / 0x8DF3B30;
   cof-5936 0x2C0E4BC / 0x248CFE4 / 0x2431550 / 0x2C0E4B0 / 0x242F340.
   Reference-function counts corroborate the roles (currententity 39-47,
   pstudiohdr 27-32, r_model 8-9, r_origin ~20-25, g_ChromeOrigin 3-4).
4. The tiny accessors have no unique strict-window signature (their
   wildcarded bodies match 6-84 functions per binary), so every accessor
   emits func_sig_allow_across_function_boundary; the across window was
   measured unique (1 match) for all 28 accessor/binary combinations.

R_StudioDrawModel:

1. The pStudioAPI locator above yields the studio object; the interface
   entry is studio+4 and R_StudioDrawPlayer is studio+8.
2. Gates: dword0 == 1, +4/+8 function starts, and studio+8 must equal the
   verified R_StudioDrawPlayer artifact func_va (DAG input). The source's
   dead-player branch calls R_StudioDrawPlayer from R_StudioDrawModel, so
   the direct call/jmp family of the +4 entry is recorded as corroboration
   (GCC .part.N clones may hide the edge on Linux).

Discovery never uses a byte signature or a prior artifact signature.
"""

from pathlib import Path

from ida_analyze_util import (
    _inspect_function_via_mcp,
    _load_yaml_mapping,
    _output_for_symbol,
    parse_mcp_result,
    write_func_yaml,
    write_gv_yaml,
)

HL_STUDIO_STRING = "Couldn't get client .dll studio model rendering interface.  Version mismatch?\n"
SVC_STUDIO_STRING = "Couldn't get client library studio model rendering interface. Version mismatch?\n"
PLAYER_FMT_STRING = "models/player/%s/%s.mdl"
SETUP_SLOT_OFFSET = 0x7C
TABLE_DWORDS = 45
MIN_TABLE_CODE_RUN = 43

_LOCATE_SHARED_PY = r"""
import ida_bytes
import ida_funcs
import ida_nalt
import ida_segment
import idaapi
import idautils
import idc
import json
import traceback

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

def direct_transfer_targets(func_start):
    # GCC .part.N cold clones hold the player-model format reference while
    # the interface entry only tail-jumps to them; collect every direct
    # call/jmp target of the entry so the semantic check can follow.
    out = set()
    for ea in func_items(func_start):
        for target in idautils.CodeRefsFrom(int(ea), 0):
            out.add(int(target))
    return out
"""

LOCATE_PY = (
    _LOCATE_SHARED_PY
    + r"""
STUDIO_STR = STUDIO_STR_PLACEHOLDER
FMT_STR = 'models/player/%s/%s.mdl'
SETUP_SLOT_OFF = 0x7C
TABLE_DWORDS = 45
MIN_TABLE_CODE_RUN = 43

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
)

LOCATE_DRAW_PLAYER_PY = (
    _LOCATE_SHARED_PY
    + r"""
STUDIO_STR = STUDIO_STR_PLACEHOLDER
FMT_STR = 'models/player/%s/%s.mdl'

def validate_pstudio(cand, form, insn_text):
    # cand is a candidate &pStudioAPI VA; its static image dword must point
    # at the writable studio object {1, R_StudioDrawModel, R_StudioDrawPlayer}.
    if not is_writable_data(cand):
        return None
    studio_ea = ida_bytes.get_dword(int(cand))
    if studio_ea == 0 or not is_writable_data(studio_ea):
        return None
    if ida_bytes.get_dword(int(studio_ea)) != 1:
        return None
    slots = []
    for offset in (4, 8):
        value = ida_bytes.get_dword(int(studio_ea) + offset)
        if value == 0 or not is_exec(value):
            return None
        fn = ida_funcs.get_func(int(value))
        if fn is None or int(fn.start_ea) != int(value):
            return None
        slots.append(value)
    return {'pstudio_ea': int(cand), 'pstudio_seg': seg_name(cand),
            'studio_ea': int(studio_ea), 'studio_seg': seg_name(studio_ea),
            'draw_model': int(slots[0]), 'draw_player': int(slots[1]),
            'form': form, 'insn': insn_text}

def main():
    strs = find_exact_strings(STUDIO_STR)
    if len(strs) != 1:
        return {'error': 'studio interface string count %d' % len(strs)}
    owners = functions_for_string(strs[0])
    if not owners:
        return {'error': 'studio interface string has no owning function'}
    cands = {}
    for own in owners:
        for ea in func_items(own):
            for off, value in absolute_data_operands(ea):
                info = validate_pstudio(value, 'absolute', '%x: %s' % (ea, disasm(ea)))
                if info and value not in cands:
                    cands[value] = info
        base = pic_anchor(own)
        if base:
            for item in pic_ebx_displacements(own, base):
                info = validate_pstudio(item['resolved'], 'pic', item['disasm'])
                if info and item['resolved'] not in cands:
                    cands[item['resolved']] = info
    if len(cands) != 1:
        return {'error': 'pStudioAPI candidates: %d' % len(cands),
                'cands': [hex(t) for t in sorted(cands)]}
    pstudio_ea, info = next(iter(cands.items()))
    draw_player = info['draw_player']
    fmts = find_exact_strings(FMT_STR)
    if not fmts:
        return {'error': 'player model format string missing',
                'pstudio_ea': hex(pstudio_ea)}
    fmt_owners = []
    for fmt_ea in fmts:
        fmt_owners.extend(functions_for_string(fmt_ea))
    fn = ida_funcs.get_func(int(draw_player))
    return {
        'pointer_size': 4,
        'string_ea': hex(strs[0]),
        'owners': [hex(x) for x in owners],
        'pstudio_ea': hex(pstudio_ea),
        'pstudio_seg': info['pstudio_seg'],
        'studio_ea': hex(info['studio_ea']),
        'studio_seg': info['studio_seg'],
        'anchor_form': info['form'],
        'anchor_insn': info['insn'],
        'draw_model': hex(info['draw_model']),
        'draw_player': hex(draw_player),
        'draw_player_end': hex(int(fn.end_ea)) if fn else None,
        'fmt_count': len(fmts),
        'fmt_owners': [hex(x) for x in sorted(set(fmt_owners))],
        'draw_refs_fmt': references_string(draw_player, fmts),
        'draw_transfers': [hex(x) for x in sorted(direct_transfer_targets(draw_player))],
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
)


LOCATE_STUDIO_SLOT_PY = (
    _LOCATE_SHARED_PY
    + r"""
STUDIO_STR = STUDIO_STR_PLACEHOLDER
SLOT_OFF = SLOT_OFF_PLACEHOLDER
TABLE_DWORDS = 45
MIN_TABLE_CODE_RUN = 43

ADD_IMM32_OPS = (0x05, 0x0D, 0x15, 0x1D, 0x2D, 0x35, 0x3D)

def validate_table_run(cand):
    if not is_writable_data(cand):
        return None
    run = 0
    for i in range(TABLE_DWORDS):
        value = ida_bytes.get_dword(int(cand) + i * 4)
        if value != 0 and is_exec(value):
            run += 1
    if run < MIN_TABLE_CODE_RUN:
        return None
    return run

def got_anchor(func_start):
    # Generalized call-thunk/add reg, imm32 prologue anchor (eax..edi short
    # forms and 81 /r long forms); used only to drop structural refs to the
    # GOT anchor itself.
    fn = ida_funcs.get_func(int(func_start))
    if fn is None:
        return None
    ea = int(fn.start_ea)
    for _ in range(10):
        insn = idautils.DecodeInstruction(ea)
        if not insn or insn.size <= 0:
            return None
        raw = ida_bytes.get_bytes(ea, insn.size) or b''
        if raw and len(raw) >= 5 and raw[0] in ADD_IMM32_OPS:
            imm = int.from_bytes(raw[1:5], 'little', signed=True)
            return (ea + imm) & 0xFFFFFFFF
        if raw and len(raw) >= 6 and raw[0] == 0x81 and 0xC0 <= raw[1] <= 0xC7:
            imm = int.from_bytes(raw[2:6], 'little', signed=True)
            return (ea + imm) & 0xFFFFFFFF
        ea += insn.size
    return None

def disp32_operand_offset(insn):
    # Offset of a 4-byte displacement/value operand inside the instruction;
    # stack operands and disp8 forms never span 4 bytes at the tail.
    for op in insn.ops:
        if int(op.type) == int(idaapi.o_void):
            break
        offb = int(getattr(op, 'offb', 0) or 0)
        if int(op.type) in (int(idaapi.o_mem), int(idaapi.o_displ)) and offb:
            if int(insn.size) - offb >= 4:
                return offb
    return 0

def reg_relative_disp32(insn, offb, pic_fn):
    # True when the disp32 at offb is register-based; that is the GOTOFF PIC
    # form whose embedded dword is var-GOT, not an address. On x86 any o_displ
    # operand has a base register (op.phrase is its number and eax == 0, so
    # truthiness must not be tested), while absolute accesses are o_mem.
    # pic_fn additionally requires the accessor's GOT-anchor prologue, so
    # non-PIC binaries never take the GOTOFF path even on stray o_displ ops.
    if pic_fn is None:
        return False
    for op in insn.ops:
        if int(op.type) == int(idaapi.o_void):
            break
        if int(getattr(op, 'offb', 0) or 0) == int(offb):
            return int(op.type) == int(idaapi.o_displ)
    return False

def gotoff_addend(ea, offb, target):
    # SvEngine GOTOFF sites embed var-GOT with no relocation: the runtime
    # dword must be rebased by the GOT RVA to yield the variable address.
    embedded = ida_bytes.get_dword(int(ea) + int(offb))
    if embedded is None or embedded == idaapi.BADADDR:
        return 0
    return (int(target) - int(embedded)) & 0xFFFFFFFF

def insn_direction(ea, insn):
    # lea counts as read: SvEngine's GOTOFF address-of feeds the real load.
    mnem = (idc.print_insn_mnem(int(ea)) or '').lower()
    if mnem in ('lea', 'fld', 'fild', 'flds', 'fldl'):
        return 'read'
    if mnem in ('fst', 'fstp', 'fistp', 'fists'):
        return 'write'
    if mnem in ('mov', 'movss', 'movsd', 'movups', 'movaps', 'movd', 'movq',
                'movlps', 'movhps', 'movlpd', 'movhpd'):
        op0_mem = int(insn.ops[0].type) in (
            int(idaapi.o_mem), int(idaapi.o_displ), int(idaapi.o_phrase))
        return 'write' if op0_mem else 'read'
    return None

def writable_refs(ea):
    return [int(x) for x in idautils.DataRefsFrom(int(ea)) if is_writable_data(int(x))]

def cluster_bases(refs):
    out = []
    for value in sorted(set(refs)):
        if out and value - out[-1][-1] <= 8:
            out[-1].append(value)
        else:
            out.append([value])
    return [group[0] for group in out]

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
                if value in tables:
                    continue
                run = validate_table_run(value)
                if run is not None:
                    tables[value] = run
        base = pic_anchor(own)
        if base:
            for item in pic_ebx_displacements(own, base):
                value = item['resolved']
                if value in tables:
                    continue
                run = validate_table_run(value)
                if run is not None:
                    tables[value] = run
    if len(tables) != 1:
        return {'error': 'engine_studio_api table candidates: %d' % len(tables),
                'tables': [hex(t) for t in sorted(tables)]}
    table_ea, code_run = next(iter(tables.items()))
    slot_va = ida_bytes.get_dword(int(table_ea) + int(SLOT_OFF))
    fn = ida_funcs.get_func(int(slot_va)) if slot_va else None
    if fn is None or int(fn.start_ea) != int(slot_va):
        return {'error': 'slot function is not a function start', 'table_ea': hex(table_ea),
                'slot_va': hex(int(slot_va or 0))}
    anchor = got_anchor(slot_va)
    reads = []
    writes = []
    ref_insns = {}
    insns = []
    for ea in func_items(slot_va):
        insn = idautils.DecodeInstruction(ea)
        if not insn:
            continue
        offb = disp32_operand_offset(insn)
        if not offb:
            continue
        direction = insn_direction(ea, insn)
        targets = [x for x in writable_refs(ea) if anchor is None or x != anchor]
        insns.append({'ea': hex(int(ea)), 'offb': offb, 'dir': direction,
                      'targets': [hex(x) for x in targets],
                      'disasm': disasm(ea)})
        for target in targets:
            addend = (gotoff_addend(ea, offb, target)
                      if reg_relative_disp32(insn, offb, anchor) else 0)
            ref_insns.setdefault(target, []).append(
                {'ea': int(ea), 'len': int(insn.size), 'offb': offb, 'addend': addend})
            if direction == 'read':
                reads.append(target)
            elif direction == 'write':
                writes.append(target)
    read_bases = cluster_bases(reads)
    write_bases = cluster_bases(writes)
    gv_refs = {}
    for base in read_bases + write_bases:
        for item in ref_insns.get(base, ()):
            gv_refs[hex(base)] = {'ea': hex(item['ea']), 'len': item['len'], 'offb': item['offb'],
                                  'addend': item['addend'], 'disasm': disasm(item['ea'])}
            break
    return {
        'pointer_size': 4,
        'string_ea': hex(strs[0]),
        'owners': [hex(x) for x in owners],
        'table_ea': hex(table_ea),
        'table_seg': seg_name(table_ea),
        'code_run': code_run,
        'slot_off': hex(int(SLOT_OFF)),
        'slot_va': hex(int(slot_va)),
        'slot_end': hex(int(fn.end_ea)),
        'got_anchor': hex(anchor) if anchor is not None else None,
        'read_bases': [hex(x) for x in read_bases],
        'write_bases': [hex(x) for x in write_bases],
        'ref_counts': {hex(t): len({int(f.start_ea) for f in
                                    (ida_funcs.get_func(int(x)) for x in idautils.DataRefsTo(t))
                                    if f is not None})
                       for t in sorted(set(reads) | set(writes))},
        'gv_refs': gv_refs,
        'insns': insns,
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
)


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


async def locate_draw_player(session, studio_string):
    try:
        code = LOCATE_DRAW_PLAYER_PY.replace("STUDIO_STR_PLACEHOLDER", repr(studio_string))
        payload = parse_mcp_result(await session.call_tool("py_eval", {"code": code}))
    except Exception:  # noqa: BLE001 - MCP failures fail closed.
        return None
    if not isinstance(payload, dict):
        return None
    if payload.get("error") or payload.get("pointer_size") != 4:
        return payload
    required = ("pstudio_ea", "studio_ea", "draw_player", "fmt_owners", "draw_transfers")
    if any(field not in payload for field in required):
        return None
    return payload


def _setup_player_model_artifact(new_binary_dir, platform, image_base):
    path = Path(new_binary_dir) / f"studioapi_SetupPlayerModel.{platform}.yaml"
    artifact = _load_yaml_mapping(path)
    if not artifact or artifact.get("func_name") != "studioapi_SetupPlayerModel":
        return None
    try:
        value = artifact["func_va"]
        func_ea = int(value, 0) if isinstance(value, str) else int(value)
    except (TypeError, ValueError, KeyError):
        return None
    if func_ea < int(image_base):
        return None
    return func_ea


async def preprocess_studio_draw_player(
    session,
    expected_outputs,
    platform,
    image_base,
    *,
    target_name,
    studio_string,
    new_binary_dir,
    debug=False,
):
    if platform not in {"windows", "linux"}:
        return False
    output = _output_for_symbol(expected_outputs, target_name)
    if output is None:
        return False
    setup_va = _setup_player_model_artifact(new_binary_dir, platform, image_base)
    if setup_va is None:
        if debug:
            print(f"  {target_name}: missing studioapi_SetupPlayerModel artifact")
        return False
    located = await locate_draw_player(session, studio_string)
    if located is None or located.get("error") or located.get("pointer_size") != 4:
        if debug:
            print(f"  {target_name}: locator failed {located}")
        return False
    try:
        pstudio_ea = int(located["pstudio_ea"], 0)
        draw_ea = int(located["draw_player"], 0)
        fmt_owners = [int(x, 0) for x in located["fmt_owners"]]
        transfers = [int(x, 0) for x in located["draw_transfers"]]
    except (TypeError, ValueError):
        return False
    if pstudio_ea < int(image_base) or draw_ea < int(image_base):
        return False
    # Semantic gate: after the entry family (the interface entry plus its
    # direct call/jmp targets, which cover GCC .part.N cold clones), the only
    # remaining "models/player/%s/%s.mdl" owner must be the verified
    # studioapi_SetupPlayerModel artifact.
    entry_family = {draw_ea} | set(transfers)
    remaining = [x for x in fmt_owners if x not in entry_family]
    if len(remaining) != 1 or remaining[0] != setup_va:
        if debug:
            print(
                f"  {target_name}: format-string owner cross-check failed "
                f"owners={located['fmt_owners']} setup={hex(setup_va)}"
            )
        return False
    if not bool(located.get("draw_refs_fmt")) and not any(x in transfers for x in fmt_owners):
        if debug:
            print(f"  {target_name}: player model format unreachable from the entry")
        return False
    function = await _inspect_function_via_mcp(session, draw_ea, image_base, target_name)
    allow_across = False
    if not function or not function.get("func_sig"):
        # Short Linux entries jump straight into their .part.N clone; the
        # across-boundary window still starts at the entry and only grows the
        # validated extent.
        function = await _inspect_function_via_mcp(
            session, draw_ea, image_base, target_name, allow_across_function_boundary=True
        )
        allow_across = function is not None and bool(function.get("func_sig"))
    if not function or not function.get("func_sig"):
        if debug:
            print(f"  {target_name}: failed to inspect entry function {located['draw_player']}")
        return False
    try:
        func_va = int(function["func_va"], 0)
    except (TypeError, ValueError):
        return False
    if func_va != draw_ea:
        return False
    if debug:
        print(
            f"  {target_name}: pstudio={located['pstudio_ea']} "
            f"({located.get('anchor_form')}, seg {located.get('pstudio_seg')}) "
            f"studio={located['studio_ea']} draw_player={located['draw_player']} "
            f"owners={located.get('owners')}"
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


SLOT_SHAPE_READ = "read"
SLOT_SHAPE_WRITE = "write"
SLOT_SHAPE_COPY12 = "copy12"


async def locate_studio_slot(session, studio_string, slot_offset):
    code = LOCATE_STUDIO_SLOT_PY.replace("STUDIO_STR_PLACEHOLDER", repr(studio_string)).replace(
        "SLOT_OFF_PLACEHOLDER", hex(int(slot_offset))
    )
    try:
        payload = parse_mcp_result(await session.call_tool("py_eval", {"code": code}))
    except Exception:  # noqa: BLE001 - MCP failures fail closed.
        return None
    if not isinstance(payload, dict):
        return None
    if payload.get("error") or payload.get("pointer_size") != 4:
        return payload
    required = ("table_ea", "slot_va", "read_bases", "write_bases", "gv_refs")
    if any(field not in payload for field in required):
        return None
    return payload


def _shape_gv_bases(located, shape):
    try:
        reads = [int(x, 0) for x in located["read_bases"]]
        writes = [int(x, 0) for x in located["write_bases"]]
    except (TypeError, ValueError):
        return None
    if shape == SLOT_SHAPE_READ:
        if len(reads) == 1 and not writes:
            return reads
    elif shape == SLOT_SHAPE_WRITE:
        if len(writes) == 1 and not reads:
            return writes
    elif shape == SLOT_SHAPE_COPY12:
        if len(reads) == 1 and len(writes) == 1 and reads[0] != writes[0]:
            return reads + writes
    return None


async def preprocess_studio_slot(
    session,
    expected_outputs,
    platform,
    image_base,
    *,
    func_name,
    slot_offset,
    shape,
    gv_names,
    studio_string,
    debug=False,
):
    if platform not in {"windows", "linux"}:
        return False
    func_output = _output_for_symbol(expected_outputs, func_name)
    gv_outputs = [_output_for_symbol(expected_outputs, name) for name in gv_names]
    if func_output is None or any(output is None for output in gv_outputs):
        return False
    located = await locate_studio_slot(session, studio_string, slot_offset)
    if located is None or located.get("error") or located.get("pointer_size") != 4:
        if debug:
            print(f"  {func_name}: slot locator failed {located}")
        return False
    try:
        table_ea = int(located["table_ea"], 0)
        slot_ea = int(located["slot_va"], 0)
    except (TypeError, ValueError):
        return False
    if table_ea < int(image_base) or slot_ea < int(image_base):
        return False
    gv_bases = _shape_gv_bases(located, shape)
    if gv_bases is None or len(gv_bases) != len(gv_names):
        if debug:
            print(
                f"  {func_name}: shape gate failed reads={located.get('read_bases')} "
                f"writes={located.get('write_bases')} shape={shape}"
            )
        return False
    gv_refs = located["gv_refs"]
    gv_items = []
    for base in gv_bases:
        ref = gv_refs.get(hex(base))
        if not ref or not ref.get("offb"):
            if debug:
                print(f"  {func_name}: no disp32 reference for gv {hex(base)}")
            return False
        gv_items.append((base, int(ref["ea"], 0), int(ref["len"]), int(ref["offb"]), int(ref.get("addend") or 0)))
    function = await _inspect_function_via_mcp(session, slot_ea, image_base, func_name)
    allow_across = False
    if not function or not function.get("func_sig"):
        # The tiny accessors have no unique strict-window signature (their
        # wildcarded bodies match many functions), so the across-boundary
        # window anchored at the same entry is the primary form.
        function = await _inspect_function_via_mcp(
            session, slot_ea, image_base, func_name, allow_across_function_boundary=True
        )
        allow_across = function is not None and bool(function.get("func_sig"))
    if not function or not function.get("func_sig"):
        if debug:
            print(f"  {func_name}: failed to inspect slot function {located['slot_va']}")
        return False
    try:
        func_va = int(function["func_va"], 0)
    except (TypeError, ValueError):
        return False
    if func_va != slot_ea:
        return False
    if debug:
        print(
            f"  {func_name}: table={located['table_ea']} ({located.get('table_seg')}, "
            f"code_run {located.get('code_run')}) slot={located['slot_va']} "
            f"owners={located.get('owners')} gv={[hex(b) for b in gv_bases]}"
        )
    func_payload = {
        "func_name": func_name,
        "func_va": function["func_va"],
        "func_rva": function["func_rva"],
        "func_size": function["func_size"],
        "func_sig": function["func_sig"],
    }
    if allow_across:
        func_payload["func_sig_allow_across_function_boundary"] = True
    write_func_yaml(func_output, func_payload)
    for index, (gv_name, (base, insn_ea, insn_len, insn_disp, pic_addend)) in enumerate(zip(gv_names, gv_items)):
        gv_payload = {
            "gv_name": gv_name,
            "gv_va": hex(base),
            "gv_rva": hex(base - int(image_base)),
            "gv_sig": function["func_sig"],
            "gv_sig_va": function["func_va"],
            "gv_inst_offset": hex(insn_ea - slot_ea),
            "gv_inst_length": hex(insn_len),
            "gv_inst_disp": hex(insn_disp),
        }
        if pic_addend:
            # Register-relative disp32 (GOTOFF): the embedded dword is
            # var-GOT and must be rebased by the GOT RVA at decode time.
            gv_payload["gv_pic_addend"] = hex(pic_addend)
        if allow_across:
            gv_payload["gv_sig_allow_across_function_boundary"] = True
        write_gv_yaml(gv_outputs[index], gv_payload)
    return True


def _r_studio_draw_player_artifact(new_binary_dir, platform, image_base):
    path = Path(new_binary_dir) / f"R_StudioDrawPlayer.{platform}.yaml"
    artifact = _load_yaml_mapping(path)
    if not artifact or artifact.get("func_name") != "R_StudioDrawPlayer":
        return None
    try:
        value = artifact["func_va"]
        func_ea = int(value, 0) if isinstance(value, str) else int(value)
    except (TypeError, ValueError, KeyError):
        return None
    if func_ea < int(image_base):
        return None
    return func_ea


async def preprocess_studio_draw_model(
    session,
    expected_outputs,
    platform,
    image_base,
    *,
    target_name,
    studio_string,
    new_binary_dir,
    debug=False,
):
    if platform not in {"windows", "linux"}:
        return False
    output = _output_for_symbol(expected_outputs, target_name)
    if output is None:
        return False
    draw_player_va = _r_studio_draw_player_artifact(new_binary_dir, platform, image_base)
    if draw_player_va is None:
        if debug:
            print(f"  {target_name}: missing R_StudioDrawPlayer artifact")
        return False
    located = await locate_draw_player(session, studio_string)
    if located is None or located.get("error") or located.get("pointer_size") != 4:
        if debug:
            print(f"  {target_name}: pStudioAPI locator failed {located}")
        return False
    try:
        pstudio_ea = int(located["pstudio_ea"], 0)
        draw_ea = int(located["draw_model"], 0)
        located_player_ea = int(located["draw_player"], 0)
    except (TypeError, ValueError):
        return False
    if pstudio_ea < int(image_base) or draw_ea < int(image_base):
        return False
    # The studio object's +8 slot is the verified R_StudioDrawPlayer
    # artifact; that equality anchors the interface table so studio+4 is
    # R_StudioDrawModel by elimination.
    if located_player_ea != draw_player_va:
        if debug:
            print(
                f"  {target_name}: studio+8 {hex(located_player_ea)} does not match the "
                f"R_StudioDrawPlayer artifact {hex(draw_player_va)}"
            )
        return False
    function = await _inspect_function_via_mcp(session, draw_ea, image_base, target_name)
    allow_across = False
    if not function or not function.get("func_sig"):
        function = await _inspect_function_via_mcp(
            session, draw_ea, image_base, target_name, allow_across_function_boundary=True
        )
        allow_across = function is not None and bool(function.get("func_sig"))
    if not function or not function.get("func_sig"):
        if debug:
            print(f"  {target_name}: failed to inspect entry function {located['draw_model']}")
        return False
    try:
        func_va = int(function["func_va"], 0)
    except (TypeError, ValueError):
        return False
    if func_va != draw_ea:
        return False
    if debug:
        print(
            f"  {target_name}: pstudio={located['pstudio_ea']} "
            f"studio={located['studio_ea']} draw_model={located['draw_model']} "
            f"draw_player={located['draw_player']}"
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
