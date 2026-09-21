"""Direct locators for StudioSetupLighting / StudioSetupModel table slots.

engine_studio_api_t (common/r_studioint.h) stores:

- studioapi_SetupModel at slot 20 (offset 0x50). That wrapper writes
  ``*ppbodypart = &pbodypart`` / ``*ppsubmodel = &psubmodel``.
- R_StudioSetupLighting at slot 24 (offset 0x60). The body assigns
  r_ambientlight from alight_t.ambientlight, r_shadelight from the
  int-to-float conversion of alight_t.shadelight, r_plightvec from
  VectorCopy through the alight_t.plightvec pointer at offset 0x14, and
  r_colormix from VectorCopy(alight_t.color) after the r_icolormix
  ``* 0xC0FF & 0xFF00`` packing.

Discovery reuses locate_studio_slot. GV addresses come from verified
instruction operands in the slot function, never from a prior artifact
signature or a source-order guess.
"""

from ida_analyze_util import (
    _inspect_function_via_mcp,
    _output_for_symbol,
    parse_mcp_result,
    write_func_yaml,
)
from ida_preprocessor_scripts._direct_gv_common import write_located_globals
from ida_preprocessor_scripts._studio_player_model_common import (
    HL_STUDIO_STRING,
    SVC_STUDIO_STRING,
    locate_studio_slot,
)

SLOT_SETUP_MODEL = 20 * 4
SLOT_SETUP_LIGHTING = 24 * 4

_RECOVER_SHARED_PY = r"""
import ida_bytes
import ida_funcs
import ida_segment
import idaapi
import idautils
import idc
import json
import traceback

ESP, EBP = 4, 5
# cdecl volatile integer registers: a call clobbers them, so tracked load
# origins must not survive one (e.g. __ftol returns its result in eax).
CALL_CLOBBER = (0, 1, 2)
O_REG = int(idaapi.o_reg)
O_MEM = int(idaapi.o_mem)
O_PHRASE = int(idaapi.o_phrase)
O_DISPL = int(idaapi.o_displ)
O_IMM = int(idaapi.o_imm)
ADD_IMM32_OPS = (0x05, 0x0D, 0x15, 0x1D, 0x2D, 0x35, 0x3D)

def is_mapped(ea):
    return ida_segment.getseg(int(ea)) is not None

def is_writable_data(ea):
    seg = ida_segment.getseg(int(ea))
    if seg is None or int(ea) == 0:
        return False
    perms = int(getattr(seg, 'perm', 0))
    executable = int(getattr(ida_segment, 'SEGPERM_EXEC', 1))
    writable = int(getattr(ida_segment, 'SEGPERM_WRITE', 2))
    return bool(perms & writable) and not bool(perms & executable)

def got_anchor(func_start):
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

def disp32_offb(insn):
    for op in insn.ops:
        if int(op.type) == int(idaapi.o_void):
            break
        offb = int(getattr(op, 'offb', 0) or 0)
        if int(op.type) in (O_MEM, O_DISPL, O_IMM) and offb and int(insn.size) - offb >= 4:
            return offb
    return 0

def mem_base_disp(op):
    typ = int(op.type)
    if typ == O_PHRASE:
        return int(op.reg), 0
    if typ == O_DISPL:
        return int(op.reg), int(op.addr) & 0xFFFFFFFF
    return None, None

def writable_refs(ea):
    return [int(x) for x in idautils.DataRefsFrom(int(ea)) if is_writable_data(int(x))]

def resolved_mem_gv(ea, insn, op, pic_fn):
    typ = int(op.type)
    offb = int(getattr(op, 'offb', 0) or 0)
    if typ == O_MEM and offb and int(insn.size) - offb >= 4:
        value = int(ida_bytes.get_dword(int(ea) + offb))
        if is_writable_data(value):
            return value, offb
    if typ == O_DISPL and offb and int(insn.size) - offb >= 4:
        refs = writable_refs(ea)
        if pic_fn is not None:
            refs = [x for x in refs if x != pic_fn]
        if len(refs) == 1:
            return refs[0], offb
        value = int(ida_bytes.get_dword(int(ea) + offb))
        if pic_fn is not None:
            resolved = (int(pic_fn) + value) & 0xFFFFFFFF
            if is_writable_data(resolved):
                return resolved, offb
        if is_writable_data(value):
            return value, offb
    return None, 0

def first_mem_op(insn):
    for op in insn.ops:
        if int(op.type) in (O_MEM, O_DISPL, O_PHRASE):
            return op
    return None

def is_outparam_dest(op):
    typ = int(op.type)
    if typ not in (O_PHRASE, O_DISPL):
        return False
    base = int(op.reg)
    if base in (ESP, EBP):
        return False
    if typ == O_DISPL and (int(op.addr) & 0xFFFFFFFF) != 0:
        return False
    return True

def imm32_writable(ea, insn, op):
    if int(op.type) != O_IMM:
        return None, 0
    offb = int(getattr(op, 'offb', 0) or 0)
    if not offb or int(insn.size) - offb < 4:
        return None, 0
    value = int(ida_bytes.get_dword(int(ea) + offb))
    if is_writable_data(value):
        return value, offb
    return None, 0
"""

RECOVER_LIGHTING_GVS_PY = (
    _RECOVER_SHARED_PY
    + r"""
SLOT_VA = SLOT_VA_PLACEHOLDER
import ida_idp
import ida_ua

PLIGHTVEC_DISP = 0x14
COMPONENT_SIZE = 4
COMPONENT_OFFSETS = (0, 4, 8)
FLOAT_STORE = ('fst', 'fstp', 'movss', 'movlps', 'movups', 'movaps')

def written_regs(insn, mnem):
    if mnem == 'call':
        return set(CALL_CLOBBER)
    regs = set()
    for index, op in enumerate(insn.ops):
        if int(op.type) == int(idaapi.o_void):
            break
        if int(op.type) != O_REG:
            continue
        if insn.get_canon_feature() & int(getattr(ida_idp, 'CF_CHG%d' % (index + 1))):
            reg = int(op.reg)
            name = ida_idp.get_reg_name(reg, ida_ua.get_dtype_size(op.dtype))
            # Partial-register writes invalidate the containing x86 register.
            for parent, aliases in enumerate((('eax', 'ax', 'al', 'ah'),
                    ('ecx', 'cx', 'cl', 'ch'), ('edx', 'dx', 'dl', 'dh'),
                    ('ebx', 'bx', 'bl', 'bh'), ('esp', 'sp'), ('ebp', 'bp'),
                    ('esi', 'si'), ('edi', 'di'))):
                if name in aliases:
                    reg = parent
                    break
            regs.add(reg)
    if mnem in ('mul', 'div', 'idiv', 'cdq', 'cwd') or (
            mnem == 'imul' and int(insn.ops[1].type) == int(idaapi.o_void)):
        regs.update((0, 2))
    return regs

def dword(op):
    return ida_ua.get_dtype_size(op.dtype) == COMPONENT_SIZE

def first_and_ff00(fn):
    for ea in idautils.FuncItems(int(fn.start_ea)):
        insn = idautils.DecodeInstruction(ea)
        if not insn:
            continue
        if (idc.print_insn_mnem(int(ea)) or '').lower() != 'and':
            continue
        for op in insn.ops:
            if int(op.type) == int(idaapi.o_void):
                break
            if int(op.type) == O_IMM and (int(op.value) & 0xFFFFFFFF) == 0xFF00:
                return int(ea)
    return None

def item(gv, ea, insn, offb):
    return {
        'gv_ea': int(gv),
        'insn_ea': int(ea),
        'insn_len': int(insn.size),
        'insn_disp': int(offb),
        'insn_disasm': idc.generate_disasm_line(int(ea), 0) or '',
    }

def walk_ptr_map(fn, stop_ea):
    ptr_of = {}
    stack_ids = {}
    next_id = [1]
    disp0 = set()
    disp4 = set()

    def stack_id(frame, disp):
        key = (int(frame), int(disp))
        if key not in stack_ids:
            stack_ids[key] = next_id[0]
            next_id[0] += 1
        return stack_ids[key]

    for ea in idautils.FuncItems(int(fn.start_ea)):
        if int(ea) >= int(stop_ea):
            break
        insn = idautils.DecodeInstruction(ea)
        if not insn:
            continue
        mnem = (idc.print_insn_mnem(int(ea)) or '').lower()
        op0, op1 = insn.ops[0], insn.ops[1]
        if mnem != 'mov' or not dword(op0):
            for reg in written_regs(insn, mnem):
                ptr_of.pop(reg, None)
        if mnem == 'mov' and not dword(op0):
            continue
        if mnem == 'mov' and int(op0.type) == O_REG and int(op1.type) == O_REG:
            src, dest = int(op1.reg), int(op0.reg)
            if src in ptr_of:
                ptr_of[dest] = ptr_of[src]
            else:
                ptr_of.pop(dest, None)
            continue
        if mnem != 'mov':
            if mnem in ('fild', 'movd'):
                mem_op = first_mem_op(insn)
                if mem_op is not None:
                    base, disp = mem_base_disp(mem_op)
                    if base in ptr_of and disp == 4:
                        disp4.add(ptr_of[base])
            continue
        if int(op0.type) != O_REG:
            continue
        dest = int(op0.reg)
        base, disp = mem_base_disp(op1)
        if base == ESP or (base == EBP and EBP not in ptr_of):
            ptr_of[dest] = stack_id(base, disp)
            continue
        if base in ptr_of:
            if disp == 0:
                disp0.add(ptr_of[base])
            ptr_of.pop(dest, None)
            continue
        ptr_of.pop(dest, None)
    common = disp0 & disp4
    if len(common) != 1:
        return None, sorted(disp0), sorted(disp4)
    return next(iter(common)), sorted(disp0), sorted(disp4)

def main():
    fn = ida_funcs.get_func(int(SLOT_VA))
    if fn is None or int(fn.start_ea) != int(SLOT_VA):
        return {'error': 'slot is not a function start', 'slot_va': hex(int(SLOT_VA))}
    and_ea = first_and_ff00(fn)
    if and_ea is None:
        return {'error': 'missing AND 0xFF00 packing'}
    plighting_id, disp0_ids, disp4_ids = walk_ptr_map(fn, and_ea)
    if plighting_id is None:
        return {'error': 'plighting pointer is not unique',
                'disp0': disp0_ids, 'disp4': disp4_ids}
    pic_fn = got_anchor(SLOT_VA)
    ptr_of = {}
    stack_ids = {}
    next_id = [1]
    reg_origin = {}
    xmm_origin = {}
    st0 = None
    ambient = []
    shade = []
    color = []
    plight = []

    def stack_id(frame, disp):
        key = (int(frame), int(disp))
        if key not in stack_ids:
            stack_ids[key] = next_id[0]
            next_id[0] += 1
        return stack_ids[key]

    def is_plighting(base):
        return ptr_of.get(base) == plighting_id

    def mem_load_origin(base, disp, op):
        if base is None or disp is None or not dword(op):
            return None
        if is_plighting(base):
            return ('f32', int(disp))
        if reg_origin.get(base) == ('load', PLIGHTVEC_DISP):
            return ('ptrload', PLIGHTVEC_DISP, int(disp))
        return None

    def collect_plight(origin, gv, ea, insn, offb, dest):
        if dword(dest) and origin[2] in COMPONENT_OFFSETS:
            candidate = item(gv, ea, insn, offb)
            candidate['source_disp'] = origin[2]
            plight.append(candidate)

    for ea in idautils.FuncItems(int(fn.start_ea)):
        insn = idautils.DecodeInstruction(ea)
        if not insn:
            continue
        mnem = (idc.print_insn_mnem(int(ea)) or '').lower()
        op0 = insn.ops[0]
        op1 = insn.ops[1]
        handled = mnem in ('mov', 'movss', 'cvtdq2ps')
        if not handled or (mnem == 'mov' and not dword(op0)):
            for reg in written_regs(insn, mnem):
                ptr_of.pop(reg, None)
                reg_origin.pop(reg, None)
                xmm_origin.pop(reg, None)
        if mnem == 'mov' and not dword(op0):
            continue
        if mnem.startswith('f') and mnem not in ('fild', 'fld', 'fst', 'fstp'):
            st0 = None
        if mnem == 'mov' and int(op0.type) == O_REG and int(op1.type) == O_REG:
            src = int(op1.reg)
            dest = int(op0.reg)
            if src in ptr_of:
                ptr_of[dest] = ptr_of[src]
            else:
                ptr_of.pop(dest, None)
            if src in reg_origin:
                reg_origin[dest] = reg_origin[src]
            else:
                reg_origin.pop(dest, None)
            continue
        if mnem == 'mov' and int(op0.type) == O_REG:
            dest = int(op0.reg)
            base, disp = mem_base_disp(op1)
            if base == ESP or (base == EBP and EBP not in ptr_of):
                ptr_of[dest] = stack_id(base, disp)
                reg_origin.pop(dest, None)
            elif is_plighting(base):
                ptr_of.pop(dest, None)
                reg_origin[dest] = ('load', int(disp))
            elif reg_origin.get(base) == ('load', PLIGHTVEC_DISP):
                ptr_of.pop(dest, None)
                reg_origin[dest] = ('ptrload', PLIGHTVEC_DISP, int(disp))
            else:
                ptr_of.pop(dest, None)
                reg_origin.pop(dest, None)
        if mnem == 'call':
            xmm_origin.clear()
            st0 = None
            continue
        if mnem == 'fild':
            mem_op = first_mem_op(insn)
            base, disp = mem_base_disp(mem_op) if mem_op is not None else (None, None)
            st0 = ('i2f', int(disp)) if is_plighting(base) else None
        elif mnem == 'fld':
            mem_op = first_mem_op(insn)
            base, disp = mem_base_disp(mem_op) if mem_op is not None else (None, None)
            st0 = mem_load_origin(base, disp, mem_op) if mem_op is not None else None
        elif mnem in ('fst', 'fstp'):
            mem_op = first_mem_op(insn)
            gv, offb = resolved_mem_gv(ea, insn, mem_op if mem_op is not None else op0, pic_fn)
            if gv is not None and offb:
                if st0 == ('i2f', 4):
                    shade.append(item(gv, ea, insn, offb))
                elif st0 is not None and st0[0] == 'ptrload':
                    collect_plight(st0, gv, ea, insn, offb, mem_op)
                elif int(ea) >= and_ea and mnem in FLOAT_STORE:
                    color.append(item(gv, ea, insn, offb))
            if mnem == 'fstp':
                st0 = None
        elif mnem == 'movd' and int(op0.type) == O_REG:
            base, disp = mem_base_disp(op1)
            xmm_origin[int(op0.reg)] = ('i2f', int(disp)) if is_plighting(base) else None
        elif mnem == 'cvtdq2ps' and int(op0.type) == O_REG:
            src = int(op1.reg) if int(op1.type) == O_REG else int(op0.reg)
            origin = xmm_origin.get(src)
            xmm_origin[int(op0.reg)] = origin if origin == ('i2f', 4) else None
        elif mnem == 'movss' and int(op0.type) == O_REG:
            base, disp = mem_base_disp(op1)
            xmm_origin[int(op0.reg)] = mem_load_origin(base, disp, op1)
        if mnem in ('mov', 'movss', 'movlps', 'movups', 'movaps'):
            dest_is_mem = int(op0.type) in (O_MEM, O_DISPL, O_PHRASE)
            if dest_is_mem:
                gv, offb = resolved_mem_gv(ea, insn, op0, pic_fn)
                if gv is not None and offb:
                    if mnem == 'mov' and int(op1.type) == O_REG:
                        origin = reg_origin.get(int(op1.reg))
                        if origin == ('load', 0):
                            ambient.append(item(gv, ea, insn, offb))
                        elif origin is not None and origin[0] == 'ptrload':
                            collect_plight(origin, gv, ea, insn, offb, op0)
                        elif int(ea) >= and_ea and origin in (('load', 8), ('load', 12), ('load', 16)):
                            color.append(item(gv, ea, insn, offb))
                    if mnem in FLOAT_STORE and int(op1.type) == O_REG:
                        origin = xmm_origin.get(int(op1.reg))
                        if origin == ('i2f', 4):
                            shade.append(item(gv, ea, insn, offb))
                        elif origin is not None and origin[0] == 'ptrload':
                            collect_plight(origin, gv, ea, insn, offb, op0)
                        elif int(ea) >= and_ea:
                            color.append(item(gv, ea, insn, offb))
    amb_gvs = sorted({x['gv_ea'] for x in ambient})
    sh_gvs = sorted({x['gv_ea'] for x in shade})
    if len(amb_gvs) != 1 or len(sh_gvs) != 1 or amb_gvs[0] == sh_gvs[0]:
        return {'error': 'ambient/shade not unique',
                'ambient': [hex(x) for x in amb_gvs],
                'shade': [hex(x) for x in sh_gvs]}
    color_addrs = sorted({x['gv_ea'] for x in color})
    bases = [a for a in color_addrs if (a + 4) in color_addrs and (a + 8) in color_addrs]
    if len(bases) != 1:
        return {'error': 'r_colormix cluster not unique',
                'color': [hex(x) for x in color_addrs],
                'bases': [hex(x) for x in bases]}
    mix = bases[0]
    mix_item = None
    for cand in color:
        if cand['gv_ea'] == mix:
            mix_item = cand
            break
    if mix_item is None:
        return {'error': 'r_colormix base store missing'}
    plight_addrs = sorted({x['gv_ea'] for x in plight})
    plight_pairs = {(x['gv_ea'], x['source_disp']) for x in plight}
    plight_bases = [a for a in plight_addrs
                    if all((a + disp, disp) in plight_pairs for disp in COMPONENT_OFFSETS)]
    if len(plight_bases) != 1:
        return {'error': 'r_plightvec cluster not unique',
                'plight': [hex(x) for x in plight_addrs],
                'plight_bases': [hex(x) for x in plight_bases]}
    plight_base = plight_bases[0]
    plight_item = None
    for cand in plight:
        if cand['gv_ea'] == plight_base:
            plight_item = cand
            break
    if plight_item is None:
        return {'error': 'r_plightvec base store missing'}
    return {
        'pointer_size': 4,
        'slot_va': hex(int(SLOT_VA)),
        'and_ea': hex(and_ea),
        'plighting_id': int(plighting_id),
        'r_ambientlight': ambient[0],
        'r_shadelight': shade[0],
        'r_plightvec': plight_item,
        'r_colormix': mix_item,
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

RECOVER_SETUP_MODEL_GVS_PY = (
    _RECOVER_SHARED_PY
    + r"""
SLOT_VA = SLOT_VA_PLACEHOLDER

def item(gv, ea, insn, offb):
    return {
        'gv_ea': int(gv),
        'insn_ea': int(ea),
        'insn_len': int(insn.size),
        'insn_disp': int(offb),
        'insn_disasm': idc.generate_disasm_line(int(ea), 0) or '',
    }

def main():
    fn = ida_funcs.get_func(int(SLOT_VA))
    if fn is None or int(fn.start_ea) != int(SLOT_VA):
        return {'error': 'slot is not a function start', 'slot_va': hex(int(SLOT_VA))}
    pic_fn = got_anchor(SLOT_VA)
    held = {}
    held_insn = {}
    ordered = []
    for ea in idautils.FuncItems(int(fn.start_ea)):
        insn = idautils.DecodeInstruction(ea)
        if not insn:
            continue
        mnem = (idc.print_insn_mnem(int(ea)) or '').lower()
        op0, op1 = insn.ops[0], insn.ops[1]
        if mnem == 'lea' and int(op0.type) == O_REG:
            gv, offb = resolved_mem_gv(ea, insn, op1, pic_fn)
            if gv is not None and offb:
                dest = int(op0.reg)
                held[dest] = gv
                held_insn[dest] = item(gv, ea, insn, offb)
            continue
        if mnem == 'mov' and int(op0.type) == O_REG and int(op1.type) == O_IMM:
            gv, offb = imm32_writable(ea, insn, op1)
            if gv is not None:
                dest = int(op0.reg)
                held[dest] = gv
                held_insn[dest] = item(gv, ea, insn, offb)
            continue
        if mnem == 'mov' and int(op0.type) == O_REG and int(op1.type) == O_REG:
            src = int(op1.reg)
            dest = int(op0.reg)
            if src in held:
                held[dest] = held[src]
                held_insn[dest] = held_insn[src]
            else:
                held.pop(dest, None)
                held_insn.pop(dest, None)
            continue
        if mnem != 'mov':
            continue
        if not is_outparam_dest(op0):
            continue
        if int(op1.type) == O_IMM:
            gv, offb = imm32_writable(ea, insn, op1)
            if gv is not None:
                ordered.append(item(gv, ea, insn, offb))
            continue
        if int(op1.type) == O_REG:
            src = int(op1.reg)
            if src in held_insn:
                ordered.append(held_insn[src])
    addrs = [x['gv_ea'] for x in ordered]
    if len(ordered) != 2 or addrs[0] == addrs[1]:
        return {'error': 'expected two distinct &global out-param stores',
                'hits': [hex(x) for x in addrs]}
    return {
        'pointer_size': 4,
        'slot_va': hex(int(SLOT_VA)),
        'pbodypart': ordered[0],
        'psubmodel': ordered[1],
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


def _gv_item(payload, name):
    item = payload.get(name)
    if not isinstance(item, dict):
        return None
    required = ("gv_ea", "insn_ea", "insn_len", "insn_disp")
    if any(field not in item for field in required):
        return None
    try:
        if int(item["insn_disp"]) <= 0:
            return None
    except (TypeError, ValueError):
        return None
    return item


async def _emit_slot_function(session, expected_outputs, platform, image_base, func_name, slot_ea, debug=False):
    if platform not in {"windows", "linux"}:
        return None
    output = _output_for_symbol(expected_outputs, func_name)
    if output is None:
        return None
    function = await _inspect_function_via_mcp(session, slot_ea, image_base, func_name)
    allow_across = False
    if not function or not function.get("func_sig"):
        function = await _inspect_function_via_mcp(
            session, slot_ea, image_base, func_name, allow_across_function_boundary=True
        )
        allow_across = function is not None and bool(function.get("func_sig"))
    if not function or not function.get("func_sig"):
        if debug:
            print(f"  {func_name}: failed to inspect slot function {hex(slot_ea)}")
        return None
    try:
        func_va = int(function["func_va"], 0)
        func_size = int(function["func_size"], 0)
    except (TypeError, ValueError):
        return None
    if func_va != slot_ea:
        return None
    payload = {
        "func_name": func_name,
        "func_va": function["func_va"],
        "func_rva": function["func_rva"],
        "func_size": function["func_size"],
        "func_sig": function["func_sig"],
    }
    if allow_across:
        payload["func_sig_allow_across_function_boundary"] = True
    write_func_yaml(output, payload)
    return {
        "artifact": payload,
        "function": function,
        "owner_ea": slot_ea,
        "owner_end": slot_ea + func_size,
        "allow_across": allow_across,
    }


async def _recover_gvs(session, code, slot_ea):
    try:
        payload = parse_mcp_result(await session.call_tool("py_eval", {"code": code}))
    except Exception:  # noqa: BLE001 - MCP failures fail closed.
        return None
    if not isinstance(payload, dict) or payload.get("error") or payload.get("pointer_size") != 4:
        return payload if isinstance(payload, dict) else None
    try:
        if int(payload["slot_va"], 0) != int(slot_ea):
            return None
    except (KeyError, TypeError, ValueError):
        return None
    return payload


async def _unique_slot_va(session, slot_offset, studio_strings):
    targets = set()
    for diagnostic in studio_strings:
        located = await locate_studio_slot(session, diagnostic, slot_offset)
        if located and not located.get("error") and located.get("pointer_size") == 4:
            try:
                targets.add(int(located["slot_va"], 0))
            except (KeyError, TypeError, ValueError):
                return None
    if len(targets) != 1:
        return None
    return next(iter(targets))


async def preprocess_studio_setup_lighting(
    session,
    expected_outputs,
    platform,
    image_base,
    *,
    debug=False,
):
    slot_ea = await _unique_slot_va(session, SLOT_SETUP_LIGHTING, (HL_STUDIO_STRING, SVC_STUDIO_STRING))
    if slot_ea is None:
        if debug:
            print("  R_StudioSetupLighting: unique slot 24 not found")
        return False
    owner = await _emit_slot_function(
        session, expected_outputs, platform, image_base, "R_StudioSetupLighting", slot_ea, debug=debug
    )
    if owner is None:
        return False
    code = RECOVER_LIGHTING_GVS_PY.replace("SLOT_VA_PLACEHOLDER", hex(int(slot_ea)))
    located = await _recover_gvs(session, code, slot_ea)
    names = ("r_ambientlight", "r_shadelight", "r_plightvec", "r_colormix")
    items = {name: _gv_item(located or {}, name) for name in names}
    if located is None or located.get("error") or any(item is None for item in items.values()):
        if debug:
            print(f"  R_StudioSetupLighting: gv recovery failed {located}")
        return False
    if debug:
        print("  R_StudioSetupLighting: " + ", ".join(f"{name}={hex(int(items[name]['gv_ea']))}" for name in names))
    return await write_located_globals(session, expected_outputs, platform, image_base, owner, items)


async def preprocess_studio_setup_model(
    session,
    expected_outputs,
    platform,
    image_base,
    *,
    studio_string,
    debug=False,
):
    slot_ea = await _unique_slot_va(session, SLOT_SETUP_MODEL, (studio_string,))
    if slot_ea is None:
        if debug:
            print("  studioapi_SetupModel: unique slot 20 not found")
        return False
    owner = await _emit_slot_function(
        session, expected_outputs, platform, image_base, "studioapi_SetupModel", slot_ea, debug=debug
    )
    if owner is None:
        return False
    code = RECOVER_SETUP_MODEL_GVS_PY.replace("SLOT_VA_PLACEHOLDER", hex(int(slot_ea)))
    located = await _recover_gvs(session, code, slot_ea)
    names = ("pbodypart", "psubmodel")
    items = {name: _gv_item(located or {}, name) for name in names}
    if located is None or located.get("error") or any(item is None for item in items.values()):
        if debug:
            print(f"  studioapi_SetupModel: gv recovery failed {located}")
        return False
    if debug:
        print("  studioapi_SetupModel: " + ", ".join(f"{name}={hex(int(items[name]['gv_ea']))}" for name in names))
    return await write_located_globals(session, expected_outputs, platform, image_base, owner, items)
