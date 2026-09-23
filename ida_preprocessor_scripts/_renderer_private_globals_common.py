"""Semantic direct locators shared by renderer-private engine globals."""

from ida_analyze_util import _inspect_function_via_mcp, parse_mcp_result
from ida_preprocessor_scripts._direct_gv_common import inspect_owner_artifact, write_located_globals

LOCATE_LIGHT_ARRAY_PY = r"""
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


def is_writable_data(ea):
    seg = ida_segment.getseg(int(ea))
    if seg is None or int(ea) == 0:
        return False
    perms = int(getattr(seg, 'perm', 0))
    return bool(perms & int(getattr(ida_segment, 'SEGPERM_WRITE', 2))) and not bool(
        perms & int(getattr(ida_segment, 'SEGPERM_EXEC', 4)))


def reg_name(op):
    if int(op.type) != int(idaapi.o_reg):
        return None
    try:
        return (ida_idp.get_reg_name(int(op.reg), int(getattr(op, 'dtype', 2)) and 4) or '').lower()
    except Exception:
        return None


def operand_reg_name(op):
    try:
        reg = int(getattr(op, 'reg', -1))
        return (ida_idp.get_reg_name(reg, 4) or '').lower() if reg >= 0 else None
    except Exception:
        return None


def mapped_targets(ea, insn):
    targets = {int(ref) for ref in idautils.DataRefsFrom(int(ea)) if is_writable_data(ref)}
    for op in insn.ops:
        if int(op.type) == int(idaapi.o_void):
            break
        value = None
        if int(op.type) == int(idaapi.o_imm):
            value = int(op.value) & 0xFFFFFFFF
        elif int(op.type) == int(idaapi.o_mem):
            value = int(op.addr) & 0xFFFFFFFF
        if value is not None and is_writable_data(value):
            targets.add(value)
    return targets


def disp32_offset(insn):
    for op in insn.ops:
        if int(op.type) == int(idaapi.o_void):
            break
        offb = int(getattr(op, 'offb', 0) or 0)
        if offb and int(insn.size) - offb >= 4 and int(op.type) in (
                int(idaapi.o_imm), int(idaapi.o_mem), int(idaapi.o_displ)):
            return offb
    return 0


globals().update(locals())

try:
    if idaapi.inf_is_64bit():
        raise RuntimeError('expected 32-bit x86')
    owner = ida_funcs.get_func(int(OWNER_EA))
    if owner is None or int(owner.start_ea) != int(OWNER_EA):
        raise RuntimeError('owner is not a function start')
    entries = []
    for ea in idautils.FuncItems(int(owner.start_ea)):
        insn = idautils.DecodeInstruction(int(ea))
        if not insn:
            continue
        entries.append({
            'ea': int(ea),
            'insn': insn,
            'mnem': (idc.print_insn_mnem(int(ea)) or '').lower(),
            'disasm': idc.generate_disasm_line(int(ea), 0) or '',
        })
    candidates = []
    for index, entry in enumerate(entries):
        insn = entry['insn']
        if entry['mnem'] not in ('mov', 'lea'):
            continue
        target_reg = reg_name(insn.ops[0])
        stack_slot = None
        if (
            entry['mnem'] == 'mov'
            and int(insn.ops[0].type) == int(idaapi.o_displ)
            and operand_reg_name(insn.ops[0]) in ('ebp', 'esp')
            and int(insn.ops[1].type) == int(idaapi.o_imm)
        ):
            stack_slot = (operand_reg_name(insn.ops[0]), int(insn.ops[0].addr) & 0xFFFFFFFF)
        offb = disp32_offset(insn)
        if stack_slot is not None:
            offb = int(getattr(insn.ops[1], 'offb', 0) or 0)
        if (not target_reg and stack_slot is None) or not offb:
            continue
        for target in mapped_targets(entry['ea'], insn):
            aliases = {target_reg} if target_reg else set()
            has_stride = False
            has_key = False
            for follower in entries[index + 1:]:
                fin = follower['insn']
                dst = reg_name(fin.ops[0])
                src = reg_name(fin.ops[1]) if len(fin.ops) > 1 else None
                if follower['mnem'] == 'mov' and dst and src in aliases:
                    aliases.add(dst)
                if (
                    stack_slot is not None
                    and follower['mnem'] == 'mov'
                    and dst
                    and int(fin.ops[1].type) == int(idaapi.o_displ)
                    and operand_reg_name(fin.ops[1]) == stack_slot[0]
                    and (int(fin.ops[1].addr) & 0xFFFFFFFF) == stack_slot[1]
                ):
                    aliases.add(dst)
                if follower['mnem'] in ('add', 'lea') and dst in aliases:
                    values = [int(getattr(op, 'value', -1)) for op in fin.ops]
                    addrs = [int(getattr(op, 'addr', -1)) for op in fin.ops]
                    if 0x28 in values or 0x28 in addrs:
                        has_stride = True
                for op in fin.ops:
                    if int(op.type) == int(idaapi.o_void):
                        break
                    if int(op.type) != int(idaapi.o_displ):
                        continue
                    if operand_reg_name(op) in aliases and (int(op.addr) & 0xFFFFFFFF) == 0x20:
                        has_key = True
            if has_stride and has_key:
                candidates.append({
                    'gv_ea': int(target),
                    'insn_ea': entry['ea'],
                    'insn_len': int(insn.size),
                    'insn_disp': int(offb),
                    'insn_disasm': entry['disasm'],
                })
    unique = {}
    for candidate in candidates:
        unique.setdefault(candidate['gv_ea'], candidate)
    if len(unique) != 1:
        result = json.dumps({
            'error': 'light array base is not unique',
            'candidate_count': len(unique),
            'candidates': [
                {**item, 'gv_ea': hex(item['gv_ea']), 'insn_ea': hex(item['insn_ea'])}
                for item in unique.values()
            ],
        })
    else:
        item = next(iter(unique.values()))
        result = json.dumps({
            'pointer_size': 4,
            'owner_ea': hex(int(owner.start_ea)),
            **{key: (hex(value) if key in ('gv_ea', 'insn_ea') else value) for key, value in item.items()},
        })
except Exception as exc:
    result = json.dumps({'error': str(exc), 'trace': traceback.format_exc()})
"""


async def preprocess_light_array(
    session,
    expected_outputs,
    new_binary_dir,
    platform,
    image_base,
    *,
    owner_name,
    gv_name,
    debug=False,
):
    if platform not in {"windows", "linux"}:
        return False
    owner = await inspect_owner_artifact(session, new_binary_dir, platform, image_base, owner_name)
    if owner is None:
        if debug:
            print(f"  {gv_name}: missing or invalid {owner_name} artifact")
        return False
    code = LOCATE_LIGHT_ARRAY_PY.replace("OWNER_EA_PLACEHOLDER", str(owner["owner_ea"]))
    try:
        located = parse_mcp_result(await session.call_tool("py_eval", {"code": code}))
    except Exception:  # noqa: BLE001 - MCP failures fail closed.
        return False
    if not isinstance(located, dict) or located.get("error") or located.get("pointer_size") != 4:
        if debug:
            print(f"  {gv_name}: light-array locator failed {located}")
        return False
    if debug:
        print(f"  {gv_name}: gv={located.get('gv_ea')} insn={located.get('insn_ea')} {located.get('insn_disasm', '')}")
    return await write_located_globals(
        session,
        expected_outputs,
        platform,
        image_base,
        owner,
        {gv_name: located},
    )


LOCATE_CACHE_HEAD_PY = r"""
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
LOOKBACK = 8


def is_writable_data(ea):
    seg = ida_segment.getseg(int(ea))
    if seg is None or int(ea) == 0:
        return False
    perms = int(getattr(seg, 'perm', 0))
    return bool(perms & int(getattr(ida_segment, 'SEGPERM_WRITE', 2))) and not bool(
        perms & int(getattr(ida_segment, 'SEGPERM_EXEC', 4)))


def reg_name(op):
    try:
        reg = int(getattr(op, 'reg', -1))
        return (ida_idp.get_reg_name(reg, 4) or '').lower() if reg >= 0 else None
    except Exception:
        return None


def value_sources(ea, insn):
    sources = {}
    for op in insn.ops:
        if int(op.type) == int(idaapi.o_void):
            break
        offb = int(getattr(op, 'offb', 0) or 0)
        if not offb or int(insn.size) - offb < 4:
            continue
        value = None
        if int(op.type) == int(idaapi.o_imm):
            value = int(op.value) & 0xFFFFFFFF
        elif int(op.type) == int(idaapi.o_mem):
            value = int(op.addr) & 0xFFFFFFFF
        if value is not None and is_writable_data(value):
            sources[value] = offb
    for ref in idautils.DataRefsFrom(int(ea)):
        ref = int(ref)
        if not is_writable_data(ref):
            continue
        for op in insn.ops:
            if int(op.type) == int(idaapi.o_void):
                break
            offb = int(getattr(op, 'offb', 0) or 0)
            if offb and int(insn.size) - offb >= 4:
                sources.setdefault(ref, offb)
                break
    return sources


globals().update(locals())

try:
    if idaapi.inf_is_64bit():
        raise RuntimeError('expected 32-bit x86')
    owner = ida_funcs.get_func(int(OWNER_EA))
    if owner is None or int(owner.start_ea) != int(OWNER_EA):
        raise RuntimeError('Cache_Alloc is not a function start')
    entries = []
    for ea in idautils.FuncItems(int(owner.start_ea)):
        insn = idautils.DecodeInstruction(int(ea))
        if not insn:
            continue
        entries.append({
            'ea': int(ea),
            'insn': insn,
            'mnem': (idc.print_insn_mnem(int(ea)) or '').lower(),
            'values': value_sources(int(ea), insn),
            'disasm': idc.generate_disasm_line(int(ea), 0) or '',
        })
    candidates = []
    for index, entry in enumerate(entries):
        if entry['mnem'] != 'cmp':
            continue
        cmp_regs = {reg_name(op) for op in entry['insn'].ops}
        cmp_regs.discard(None)
        window = entries[max(0, index - LOOKBACK):index + 1]
        head_sources = []
        member_values = set(entry['values'])
        for prior in window:
            if prior is entry:
                for value, offb in prior['values'].items():
                    head_sources.append((value, prior, offb))
                continue
            insn = prior['insn']
            destination = reg_name(insn.ops[0]) if int(insn.ops[0].type) == int(idaapi.o_reg) else None
            if prior['mnem'] in ('mov', 'lea') and destination in cmp_regs:
                for value, offb in prior['values'].items():
                    head_sources.append((value, prior, offb))
                    member_values.add(value)
        for head, source, offb in head_sources:
            deltas = []
            for value in member_values:
                delta = value - head
                if delta in (0x48, 0x50):
                    deltas.append(delta)
            deltas.sort()
            if not deltas or any(delta % 4 for delta in deltas):
                continue
            candidates.append({
                'gv_ea': int(head),
                'insn_ea': int(source['ea']),
                'insn_len': int(source['insn'].size),
                'insn_disp': int(offb),
                'insn_disasm': source['disasm'],
                'cmp_ea': hex(entry['ea']),
                'member_deltas': [hex(delta) for delta in deltas],
            })
    unique = {}
    for candidate in candidates:
        unique.setdefault(candidate['gv_ea'], candidate)
    if len(unique) != 1:
        result = json.dumps({
            'error': 'cache_head sentinel base is not unique',
            'candidate_count': len(unique),
            'candidates': [
                {**item, 'gv_ea': hex(item['gv_ea']), 'insn_ea': hex(item['insn_ea'])}
                for item in unique.values()
            ],
        })
    else:
        item = next(iter(unique.values()))
        result = json.dumps({
            'pointer_size': 4,
            'owner_ea': hex(int(owner.start_ea)),
            **{key: (hex(value) if key in ('gv_ea', 'insn_ea') else value) for key, value in item.items()},
        })
except Exception as exc:
    result = json.dumps({'error': str(exc), 'trace': traceback.format_exc()})
"""


async def preprocess_cache_head(
    session,
    expected_outputs,
    new_binary_dir,
    platform,
    image_base,
    *,
    debug=False,
):
    owner_name = "Cache_Alloc"
    gv_name = "cache_head"
    owner = await inspect_owner_artifact(session, new_binary_dir, platform, image_base, owner_name)
    if owner is None:
        return False
    code = LOCATE_CACHE_HEAD_PY.replace("OWNER_EA_PLACEHOLDER", str(owner["owner_ea"]))
    try:
        located = parse_mcp_result(await session.call_tool("py_eval", {"code": code}))
    except Exception:  # noqa: BLE001 - MCP failures fail closed.
        return False
    if not isinstance(located, dict) or located.get("error") or located.get("pointer_size") != 4:
        if debug:
            print(f"  cache_head: sentinel locator failed {located}")
        return False
    if debug:
        print(
            f"  cache_head: gv={located.get('gv_ea')} cmp={located.get('cmp_ea')} "
            f"member={located.get('member_deltas')} insn={located.get('insn_disasm', '')}"
        )
    return await write_located_globals(
        session,
        expected_outputs,
        platform,
        image_base,
        owner,
        {gv_name: located},
    )


LOCATE_REF_PARAMS_GLOBALS_PY = r"""
import ida_bytes
import ida_funcs
import ida_idp
import ida_segment
import idaapi
import idautils
import idc
import json
import re
import traceback

OWNER_EA = OWNER_EA_PLACEHOLDER
PROBES = []


def is_writable_data(ea):
    seg = ida_segment.getseg(int(ea))
    if seg is None or int(ea) == 0:
        return False
    perms = int(getattr(seg, 'perm', 0))
    return bool(perms & int(getattr(ida_segment, 'SEGPERM_WRITE', 2))) and not bool(
        perms & int(getattr(ida_segment, 'SEGPERM_EXEC', 4)))


def reg_name(op):
    try:
        reg = int(getattr(op, 'reg', -1))
        return (ida_idp.get_reg_name(reg, 4) or '').lower() if reg >= 0 else None
    except Exception:
        return None


def operand_text(ea, index):
    return (idc.print_operand(int(ea), int(index)) or '').lower()


def signed32(value):
    value = int(value) & 0xFFFFFFFF
    return value - 0x100000000 if value & 0x80000000 else value


def parsed_memory_operand(ea, index):
    text = operand_text(ea, index).replace(' ', '')
    match = re.search(r'\[(e(?:ax|bx|cx|dx|si|di|bp|sp))(?:\+([0-9a-f]+)h|\-([0-9a-f]+)h)?\]', text)
    if not match:
        return None
    value = int(match.group(2) or match.group(3) or '0', 16)
    if match.group(3):
        value = -value
    return match.group(1), value


def disp32_offset(insn):
    for op in insn.ops:
        if int(op.type) == int(idaapi.o_void):
            break
        offb = int(getattr(op, 'offb', 0) or 0)
        if offb and int(insn.size) - offb >= 4 and int(op.type) in (
                int(idaapi.o_mem), int(idaapi.o_displ), int(idaapi.o_imm)):
            return offb
    return 0


def direct_targets(ea, insn, known_bases):
    # Prefer the exact loader-relocated absolute operand.  IDA may report a
    # DataRefsFrom xref to the containing structure symbol while the encoded
    # dword names a member (notably hl-8684's client-state fields).
    absolute = []
    for op in insn.ops:
        if int(op.type) == int(idaapi.o_void):
            break
        offb = int(getattr(op, 'offb', 0) or 0)
        if int(op.type) == int(idaapi.o_mem) and offb and int(insn.size) - offb >= 4:
            value = int(ida_bytes.get_dword(int(ea) + offb))
            if is_writable_data(value):
                absolute.append(value)
    if absolute:
        return sorted(set(absolute))
    targets = []
    for ref in idautils.DataRefsFrom(int(ea)):
        ref = int(ref)
        seg = ida_segment.getseg(ref)
        if seg is not None and ida_segment.get_segm_name(seg) in ('.got', '.got.plt'):
            pointee = int(ida_bytes.get_dword(ref))
            if is_writable_data(pointee):
                targets.append(pointee)
        elif is_writable_data(ref):
            targets.append(ref)
    for op in insn.ops:
        if int(op.type) == int(idaapi.o_void):
            break
        if int(op.type) == int(idaapi.o_mem) and is_writable_data(int(op.addr)):
            targets.append(int(op.addr))
        elif int(op.type) == int(idaapi.o_displ):
            base = reg_name(op)
            if base in known_bases:
                value = (int(known_bases[base]) + signed32(op.addr)) & 0xFFFFFFFF
                if is_writable_data(value):
                    targets.append(value)
    return sorted(set(targets))


def function_candidates(start):
    fn = ida_funcs.get_func(int(start))
    if fn is None or int(fn.start_ea) != int(start):
        return []
    known_bases = {}
    reg_sources = {}
    fpu_source = None
    stores = []
    stack_bases = []
    memset_sizes = set()
    fpu_debug = []
    for ea in idautils.FuncItems(int(start)):
        insn = idautils.DecodeInstruction(int(ea))
        if not insn:
            continue
        mnem = (idc.print_insn_mnem(int(ea)) or '').lower()
        targets = direct_targets(ea, insn, known_bases)
        offb = disp32_offset(insn)
        info = None
        if len(targets) == 1 and offb:
            info = {
                'gv_ea': targets[0],
                'insn_ea': int(ea),
                'insn_len': int(insn.size),
                'insn_disp': int(offb),
                'insn_disasm': idc.generate_disasm_line(int(ea), 0) or '',
            }
        for op in insn.ops:
            if int(op.type) == int(idaapi.o_void):
                break
            if int(op.type) == int(idaapi.o_imm) and int(op.value) in (0xE8, 0xF8):
                memset_sizes.add(int(op.value))
        if mnem == 'lea' and int(insn.ops[0].type) == int(idaapi.o_reg) and int(insn.ops[1].type) == int(idaapi.o_displ):
            base = reg_name(insn.ops[1])
            if base in ('ebp', 'esp'):
                stack_bases.append((base, signed32(insn.ops[1].addr)))
        # Record a global load before mutating register state.
        if int(insn.ops[0].type) == int(idaapi.o_reg):
            destination_text = operand_text(ea, 0)
            if info is not None and mnem in ('mov', 'movss', 'movsd', 'movups', 'movaps', 'movd', 'movq', 'lea'):
                reg_sources[destination_text] = info
            elif mnem == 'mov' and int(insn.ops[1].type) == int(idaapi.o_reg):
                source_text = operand_text(ea, 1)
                if source_text in reg_sources:
                    reg_sources[destination_text] = reg_sources[source_text]
                else:
                    reg_sources.pop(destination_text, None)
            else:
                reg_sources.pop(destination_text, None)
        if mnem in ('fld', 'fild', 'flds', 'fldl') and info is not None:
            fpu_source = info
        if mnem in ('fst', 'fstp', 'fistp', 'fists'):
            fpu_debug.append({
                'ea': hex(int(ea)),
                'op_type': int(insn.ops[0].type),
                'disp': hex(int(getattr(insn.ops[0], 'addr', 0)) & 0xFFFFFFFF),
                'base': reg_name(insn.ops[0]),
                'source': None if fpu_source is None else hex(int(fpu_source['gv_ea'])),
            })
        # Associate a struct-field store with the global load feeding it.
        memory_operand = None
        if int(insn.ops[0].type) == int(idaapi.o_displ):
            memory_operand = (reg_name(insn.ops[0]), signed32(insn.ops[0].addr))
        elif mnem in ('fst', 'fstp', 'fistp', 'fists'):
            for operand_index in range(3):
                memory_operand = parsed_memory_operand(ea, operand_index)
                if memory_operand is not None:
                    break
        if memory_operand is not None:
            source = None
            if mnem in ('mov', 'movss', 'movsd', 'movups', 'movaps', 'movd', 'movq') and int(insn.ops[1].type) == int(idaapi.o_reg):
                source = reg_sources.get(operand_text(ea, 1))
            elif mnem in ('fst', 'fstp', 'fistp', 'fists'):
                source = fpu_source
                fpu_source = None
            if source is not None:
                stores.append({
                    'base': memory_operand[0],
                    'disp': memory_operand[1],
                    'source': source,
                })
        # Track address-bearing GPRs for PIC client-state member loads.
        if int(insn.ops[0].type) == int(idaapi.o_reg) and mnem not in ('push', 'pop'):
            destination = reg_name(insn.ops[0])
            next_base = None
            if mnem == 'mov' and int(insn.ops[1].type) == int(idaapi.o_reg):
                next_base = known_bases.get(reg_name(insn.ops[1]))
            elif mnem in ('mov', 'lea') and len(targets) == 1:
                next_base = int(targets[0])
            if next_base is None:
                known_bases.pop(destination, None)
            else:
                known_bases[destination] = next_base
    layouts = []
    if memset_sizes:
        # Out-of-line V_SetRefParams uses the public ref_params offsets.
        for base in sorted({item['base'] for item in stores if item['base']}):
            layouts.append((base, 0))
        # Some MSVC builds reload the ref_params pointer from the argument for
        # every field, rotating through eax/ecx/edx.  The four required field
        # offsets remain unique within the memset(sizeof(ref_params_t)) owner.
        layouts.append((None, 0))
        # The one inlined build writes the same fields into a memset local.
        for base, disp in stack_bases:
            layouts.append((base, disp))
    results = []
    for base, origin in layouts:
        by_disp = {}
        for item in stores:
            if base is None or item['base'] == base:
                by_disp.setdefault(item['disp'], item)
        wanted = [origin + 0x54, origin + 0x64, origin + 0x68, origin + 0x6C]
        if any(disp not in by_disp for disp in wanted):
            continue
        water = by_disp[wanted[0]]['source']
        sim = [by_disp[disp]['source'] for disp in wanted[1:]]
        sim_values = [int(item['gv_ea']) for item in sim]
        if sim_values != [sim_values[0], sim_values[0] + 4, sim_values[0] + 8]:
            continue
        results.append({'water': water, 'simorg': sim[0], 'layout_base': base,
                        'layout_origin': origin, 'memset_sizes': sorted(memset_sizes)})
    PROBES.append({
        'start': hex(int(start)),
        'memset_sizes': sorted(memset_sizes),
        'store_count': len(stores),
        'interesting_stores': [
            {'base': item['base'], 'disp': hex(item['disp'] & 0xFFFFFFFF),
             'source': hex(int(item['source']['gv_ea']))}
            for item in stores if item['disp'] in (0x54, 0x64, 0x68, 0x6C)
        ],
        'fpu_debug': fpu_debug[:40],
    })
    return results


globals().update(locals())

try:
    if idaapi.inf_is_64bit():
        raise RuntimeError('expected 32-bit x86')
    owner = ida_funcs.get_func(int(OWNER_EA))
    if owner is None or int(owner.start_ea) != int(OWNER_EA):
        raise RuntimeError('V_RenderView is not a function start')
    starts = {int(owner.start_ea)}
    for ea in idautils.FuncItems(int(owner.start_ea)):
        if (idc.print_insn_mnem(int(ea)) or '').lower() != 'call':
            continue
        for ref in idautils.CodeRefsFrom(int(ea), 0):
            fn = ida_funcs.get_func(int(ref))
            if fn is not None and int(fn.start_ea) == int(ref):
                starts.add(int(ref))
    matches = []
    for start in sorted(starts):
        for item in function_candidates(start):
            matches.append({'owner_ea': start, **item})
    unique = {}
    for item in matches:
        key = (item['owner_ea'], item['water']['gv_ea'], item['simorg']['gv_ea'])
        unique[key] = item
    if len(unique) != 1:
        result = json.dumps({
            'error': 'V_SetRefParams semantic candidate is not unique',
            'candidate_count': len(unique),
            'candidates': matches,
            'probes': PROBES,
        })
    else:
        item = next(iter(unique.values()))
        item['pointer_size'] = 4
        item['owner_ea'] = hex(item['owner_ea'])
        result = json.dumps(item)
except Exception as exc:
    result = json.dumps({'error': str(exc), 'trace': traceback.format_exc()})
"""


async def preprocess_ref_params_globals(
    session,
    expected_outputs,
    new_binary_dir,
    platform,
    image_base,
    *,
    debug=False,
):
    render_owner = await inspect_owner_artifact(session, new_binary_dir, platform, image_base, "V_RenderView")
    if render_owner is None:
        return False
    code = LOCATE_REF_PARAMS_GLOBALS_PY.replace("OWNER_EA_PLACEHOLDER", str(render_owner["owner_ea"]))
    try:
        located = parse_mcp_result(await session.call_tool("py_eval", {"code": code}))
    except Exception:  # noqa: BLE001 - MCP failures fail closed.
        return False
    if not isinstance(located, dict) or located.get("error") or located.get("pointer_size") != 4:
        if debug:
            print(f"  ref_params globals: locator failed {located}")
        return False
    try:
        semantic_owner_ea = int(located["owner_ea"], 0)
    except (KeyError, TypeError, ValueError):
        return False
    if semantic_owner_ea == render_owner["owner_ea"]:
        semantic_owner = render_owner
    else:
        function = await _inspect_function_via_mcp(session, semantic_owner_ea, image_base, "V_SetRefParams")
        allow_across = False
        if not function or not function.get("func_sig"):
            function = await _inspect_function_via_mcp(
                session,
                semantic_owner_ea,
                image_base,
                "V_SetRefParams",
                allow_across_function_boundary=True,
            )
            allow_across = function is not None and bool(function.get("func_sig"))
        if not function or not function.get("func_sig"):
            return False
        try:
            if int(function["func_va"], 0) != semantic_owner_ea:
                return False
            semantic_owner_end = semantic_owner_ea + int(function["func_size"], 0)
        except (KeyError, TypeError, ValueError):
            return False
        semantic_owner = {
            "function": function,
            "owner_ea": semantic_owner_ea,
            "owner_end": semantic_owner_end,
            "allow_across": allow_across,
        }
    if debug:
        print(
            f"  ref_params globals: owner={located.get('owner_ea')} "
            f"cl_waterlevel={located.get('water', {}).get('gv_ea')} "
            f"cl_simorg={located.get('simorg', {}).get('gv_ea')} "
            f"layout={located.get('layout_base')}+{located.get('layout_origin')}"
        )
    return await write_located_globals(
        session,
        expected_outputs,
        platform,
        image_base,
        semantic_owner,
        {
            "cl_waterlevel": located["water"],
            "cl_simorg": located["simorg"],
        },
    )


LOCATE_VIEWMODEL_GLOBALS_PY = r"""
import ida_bytes
import ida_funcs
import ida_idp
import ida_segment
import idaapi
import idautils
import idc
import json
import re
import traceback

OWNER_EA = OWNER_EA_PLACEHOLDER


def is_writable_data(ea):
    seg = ida_segment.getseg(int(ea))
    if seg is None or int(ea) == 0:
        return False
    perms = int(getattr(seg, 'perm', 0))
    return bool(perms & int(getattr(ida_segment, 'SEGPERM_WRITE', 2))) and not bool(
        perms & int(getattr(ida_segment, 'SEGPERM_EXEC', 4)))


def reg_name(op):
    try:
        reg = int(getattr(op, 'reg', -1))
        return (ida_idp.get_reg_name(reg, 4) or '').lower() if reg >= 0 else None
    except Exception:
        return None


def signed32(value):
    value = int(value) & 0xFFFFFFFF
    return value - 0x100000000 if value & 0x80000000 else value


def parsed_memory_operand(ea, index):
    text = (idc.print_operand(int(ea), int(index)) or '').lower().replace(' ', '')
    match = re.search(r'\[(e(?:ax|bx|cx|dx|si|di|bp|sp))(?:\+([0-9a-f]+)h|\-([0-9a-f]+)h)?\]', text)
    if match:
        value = int(match.group(2) or match.group(3) or '0', 16)
        return match.group(1), -value if match.group(3) else value
    match = re.search(r'(?:loc|dword|qword|word|byte|unk)_([0-9a-f]+)\[(e(?:ax|bx|cx|dx|si|di|bp|sp))\]', text)
    if match:
        return match.group(2), int(match.group(1), 16)
    return None


def disp32_offset(insn):
    for op in insn.ops:
        if int(op.type) == int(idaapi.o_void):
            break
        offb = int(getattr(op, 'offb', 0) or 0)
        if offb and int(insn.size) - offb >= 4 and int(op.type) != int(idaapi.o_reg):
            return offb
    return 0


def direct_targets(ea, insn, known_bases):
    targets = set()
    for ref in idautils.DataRefsFrom(int(ea)):
        ref = int(ref)
        seg = ida_segment.getseg(ref)
        if seg is not None and ida_segment.get_segm_name(seg) in ('.got', '.got.plt'):
            pointee = int(ida_bytes.get_dword(ref))
            if is_writable_data(pointee):
                targets.add(pointee)
        elif is_writable_data(ref):
            targets.add(ref)
    for index, op in enumerate(insn.ops):
        if int(op.type) == int(idaapi.o_void):
            break
        if int(op.type) == int(idaapi.o_mem) and is_writable_data(int(op.addr)):
            targets.add(int(op.addr))
        memory = None
        if int(op.type) in (int(idaapi.o_displ), int(idaapi.o_phrase)):
            memory = (reg_name(op), signed32(op.addr))
        else:
            memory = parsed_memory_operand(ea, index)
        if memory is not None and memory[0] in known_bases:
            target = (int(known_bases[memory[0]]) + int(memory[1])) & 0xFFFFFFFF
            if is_writable_data(target):
                targets.add(target)
    return sorted(targets)


def operand_displacements(ea, insn):
    values = set()
    for index, op in enumerate(insn.ops):
        if int(op.type) == int(idaapi.o_void):
            break
        if int(op.type) in (int(idaapi.o_displ), int(idaapi.o_phrase)):
            values.add(signed32(op.addr))
        memory = parsed_memory_operand(ea, index)
        if memory is not None:
            values.add(int(memory[1]))
    return values


def locate(start):
    fn = ida_funcs.get_func(int(start))
    if fn is None or int(fn.start_ea) != int(start):
        return []
    entries = []
    known_bases = {}
    for ea in idautils.FuncItems(int(start)):
        insn = idautils.DecodeInstruction(int(ea))
        if not insn:
            continue
        mnem = (idc.print_insn_mnem(int(ea)) or '').lower()
        targets = direct_targets(ea, insn, known_bases)
        offb = disp32_offset(insn)
        infos = []
        if offb:
            for target in targets:
                infos.append({
                    'gv_ea': int(target),
                    'insn_ea': int(ea),
                    'insn_len': int(insn.size),
                    'insn_disp': int(offb),
                    'insn_disasm': idc.generate_disasm_line(int(ea), 0) or '',
                    'mnem': mnem,
                })
        immediates = set()
        for op in insn.ops:
            if int(op.type) == int(idaapi.o_void):
                break
            if int(op.type) == int(idaapi.o_imm):
                immediates.add(int(op.value) & 0xFFFFFFFF)
        entries.append({
            'ea': int(ea),
            'mnem': mnem,
            'infos': infos,
            'immediates': immediates,
            'displacements': operand_displacements(ea, insn),
        })
        if int(insn.ops[0].type) == int(idaapi.o_reg) and mnem not in ('push', 'pop'):
            destination = reg_name(insn.ops[0])
            next_base = None
            if mnem == 'mov' and int(insn.ops[1].type) == int(idaapi.o_reg):
                next_base = known_bases.get(reg_name(insn.ops[1]))
            elif mnem in ('mov', 'lea') and len(targets) == 1:
                next_base = int(targets[0])
            if next_base is None:
                known_bases.pop(destination, None)
            else:
                known_bases[destination] = next_base

    events = {}
    for index, entry in enumerate(entries):
        for info in entry['infos']:
            events.setdefault(int(info['gv_ea']), []).append((index, info))

    stats = {}
    for target, target_events in events.items():
        for index, info in target_events:
            if info['mnem'] not in ('cmp', 'mov'):
                continue
            branch_window = entries[index:min(len(entries), index + 4)]
            if not any(item['mnem'] in ('jle', 'jng') for item in branch_window):
                continue
            model_window = entries[index:min(len(entries), index + 14)]
            if not any(0xB94 in item['displacements'] for item in model_window):
                continue
            stats[target] = info

    weapon_pairs = {}
    float_mnems = {'fld', 'flds', 'fldl', 'fst', 'fstp', 'movss'}
    for base, base_events in events.items():
        sequence_events = events.get(base + 4, [])
        if not sequence_events:
            continue
        for first_index, first_info in base_events:
            if first_info['mnem'] not in float_mnems:
                continue
            for sequence_index, sequence_info in sequence_events:
                if sequence_info['mnem'] != 'mov' or abs(sequence_index - first_index) > 24:
                    continue
                begin = min(first_index, sequence_index)
                end = min(len(entries), max(first_index, sequence_index) + 20)
                displacements = set().union(*(item['displacements'] for item in entries[begin:end]))
                entity_fields = {0x2DC, 0x30C, -0x86C, -0x83C}
                if len(displacements & entity_fields) < 2:
                    continue
                weapon_pairs[(base, base + 4)] = (first_info, sequence_info)

    light = {}
    for index, entry in enumerate(entries):
        if 0xAAAAAAAB not in entry['immediates']:
            continue
        window = entries[index:min(len(entries), index + 14)]
        if not any(item['mnem'] == 'mul' for item in window):
            continue
        for shrink_index in range(index, min(len(entries), index + 14)):
            shrink = entries[shrink_index]
            if shrink['mnem'] != 'shr' or 1 not in shrink['immediates']:
                continue
            for store_index in range(shrink_index + 1, min(len(entries), shrink_index + 4)):
                store = entries[store_index]
                if store['mnem'] != 'mov':
                    continue
                for info in store['infos']:
                    target = int(info['gv_ea'])
                    companion_window = entries[store_index + 1:min(len(entries), store_index + 5)]
                    has_companion = any(
                        int(other['gv_ea']) == target + 4
                        for item in companion_window
                        for other in item['infos']
                    )
                    if not has_companion:
                        light[target] = info

    if len(stats) == 1 and not light:
        expected_light = next(iter(stats)) + 0x450
        expected_events = events.get(expected_light, [])
        if expected_events:
            light[expected_light] = expected_events[0][1]

    call_store_candidates = {}
    for index, entry in enumerate(entries):
        if entry['mnem'] != 'mov' or not entry['infos']:
            continue
        window = entries[index + 1:min(len(entries), index + 7)]
        if not any(item['mnem'] == 'mov' for item in window):
            continue
        if not any(item['mnem'] == 'call' for item in window):
            continue
        for info in entry['infos']:
            call_store_candidates[int(info['gv_ea'])] = info

    if len(stats) == 1 and not light:
        stats_ea = next(iter(stats))
        nearby_call_stores = {
            key: value
            for key, value in call_store_candidates.items()
            if stats_ea < key and key - stats_ea < 0x10000
        }
        if len(nearby_call_stores) == 1:
            light = nearby_call_stores

    layout_pairs = [
        (stats_ea, light_ea)
        for stats_ea in stats
        for light_ea in light
        if light_ea - stats_ea == 0x450
    ]
    if len(layout_pairs) == 1:
        stats_ea, light_ea = layout_pairs[0]
        stats = {stats_ea: stats[stats_ea]}
        light = {light_ea: light[light_ea]}

    if len(stats) == 1:
        stats_ea = next(iter(stats))
        weapon_pairs = {
            key: value
            for key, value in weapon_pairs.items()
            if stats_ea < key[0] and key[0] - stats_ea < 0x800000
        }
        light = {
            key: value
            for key, value in light.items()
            if stats_ea < key and key - stats_ea < 0x10000
        }

    if len(stats) != 1 or len(weapon_pairs) != 1 or len(light) != 1:
        return [{
            'error': 'viewmodel semantic candidates are not unique',
            'stats': [hex(value) for value in sorted(stats)],
            'weapon_pairs': [[hex(key[0]), hex(key[1])] for key in sorted(weapon_pairs)],
            'light': [hex(value) for value in sorted(light)],
            'call_store_candidates': [hex(value) for value in sorted(call_store_candidates)],
        }]

    # envmap is the integer absolute-global test that immediately precedes the
    # cl.stats[STAT_HEALTH] test in the R_DrawViewModel early-out chain
    # (ClientDLL_IsThirdPerson / chase_active / envmap / r_drawentities /
    # cl.stats).  Scanning backwards from the cl_stats site skips the float cvar
    # tests and stops at that global.
    envmap = {}
    stats_info = next(iter(stats.values()))
    stats_index = None
    for index, entry in enumerate(entries):
        if entry['ea'] == stats_info['insn_ea']:
            stats_index = index
            break
    if stats_index is not None:
        for back in range(stats_index - 1, max(0, stats_index - 40) - 1, -1):
            info = _probe_envmap(entries, back)
            if info is not None:
                envmap = {int(info['gv_ea']): info}
                break

    if len(envmap) != 1:
        return [{
            'error': 'viewmodel envmap candidate is not unique',
            'stats': [hex(value) for value in sorted(stats)],
            'envmap': [hex(value) for value in sorted(envmap)],
        }]
    stats_item = next(iter(stats.values()))
    weapon_start, weapon_sequence = next(iter(weapon_pairs.values()))
    light_item = next(iter(light.values()))
    return [{
        'cl_stats': stats_item,
        'cl_weaponstarttime': weapon_start,
        'cl_weaponsequence': weapon_sequence,
        'cl_light_level': light_item,
        'envmap': next(iter(envmap.values())),
    }]


def _probe_envmap(entries, index):
    entry = entries[index]
    if not entry['infos']:
        return None
    insn = idautils.DecodeInstruction(entry['ea'])
    if insn is None:
        return None
    op0 = insn.ops[0]
    if entry['mnem'] == 'cmp':
        if int(op0.type) not in (int(idaapi.o_mem), int(idaapi.o_displ)):
            return None
        if int(op0.type) == int(idaapi.o_displ) and reg_name(op0) in ('esp', 'ebp'):
            return None
        for info in entry['infos']:
            if info.get('insn_disp'):
                return info
        return None
    if entry['mnem'] != 'mov' or int(op0.type) != int(idaapi.o_reg):
        return None
    src = insn.ops[1] if len(insn.ops) > 1 else None
    if src is None or int(src.type) not in (int(idaapi.o_mem), int(idaapi.o_displ)):
        return None
    if int(src.type) == int(idaapi.o_displ) and reg_name(src) in ('esp', 'ebp'):
        return None
    if index + 1 >= len(entries):
        return None
    follower = entries[index + 1]
    follower_insn = idautils.DecodeInstruction(follower['ea'])
    if follower_insn is None:
        return None
    loaded = reg_name(op0)
    tested = reg_name(follower_insn.ops[0])
    if follower['mnem'] == 'test':
        if tested != loaded or reg_name(follower_insn.ops[1]) != loaded:
            return None
    elif follower['mnem'] == 'cmp':
        if (tested != loaded
                or int(follower_insn.ops[1].type) != int(idaapi.o_imm)
                or int(follower_insn.ops[1].value) != 0):
            return None
    else:
        return None
    for info in entry['infos']:
        if info.get('insn_disp'):
            return info
    return None


globals().update(locals())

try:
    if idaapi.inf_is_64bit():
        raise RuntimeError('expected 32-bit x86')
    matches = locate(OWNER_EA)
    if len(matches) != 1 or matches[0].get('error'):
        result = json.dumps(matches[0] if matches else {'error': 'no viewmodel candidates'})
    else:
        result = json.dumps({'pointer_size': 4, **matches[0]})
except Exception as exc:
    result = json.dumps({'error': str(exc), 'trace': traceback.format_exc()})
"""


async def preprocess_viewmodel_globals(
    session,
    expected_outputs,
    new_binary_dir,
    platform,
    image_base,
    *,
    predecessor,
    debug=False,
):
    owner = await inspect_owner_artifact(session, new_binary_dir, platform, image_base, predecessor)
    if owner is None:
        return False
    code = LOCATE_VIEWMODEL_GLOBALS_PY.replace("OWNER_EA_PLACEHOLDER", str(owner["owner_ea"]))
    try:
        located = parse_mcp_result(await session.call_tool("py_eval", {"code": code}))
    except Exception:  # noqa: BLE001 - MCP failures fail closed.
        return False
    names = (
        "cl_stats",
        "cl_weaponstarttime",
        "cl_weaponsequence",
        "cl_light_level",
        "envmap",
    )
    if (
        not isinstance(located, dict)
        or located.get("error")
        or located.get("pointer_size") != 4
        or any(not isinstance(located.get(name), dict) for name in names)
    ):
        if debug:
            print(f"  viewmodel globals: locator failed {located}")
        return False
    if debug:
        values = " ".join(f"{name}={located[name].get('gv_ea')}" for name in names)
        print(f"  viewmodel globals: {values}")
    return await write_located_globals(
        session,
        expected_outputs,
        platform,
        image_base,
        owner,
        {name: located[name] for name in names},
    )


LOCATE_CSHIFT_WATER_PY = r"""
import ida_bytes
import ida_funcs
import ida_idp
import ida_segment
import idaapi
import idautils
import idc
import itertools
import json
import traceback

OWNER_EA = OWNER_EA_PLACEHOLDER


def is_writable_data(ea):
    seg = ida_segment.getseg(int(ea))
    if seg is None or int(ea) == 0:
        return False
    perms = int(getattr(seg, 'perm', 0))
    return bool(perms & int(getattr(ida_segment, 'SEGPERM_WRITE', 2))) and not bool(
        perms & int(getattr(ida_segment, 'SEGPERM_EXEC', 4)))


def disp32_offset(insn):
    for op in insn.ops:
        if int(op.type) == int(idaapi.o_void):
            break
        offb = int(getattr(op, 'offb', 0) or 0)
        if offb and int(insn.size) - offb >= 4 and int(op.type) in (
                int(idaapi.o_mem), int(idaapi.o_displ), int(idaapi.o_imm)):
            return offb
    return 0


def reg_name(op):
    try:
        reg = int(getattr(op, 'reg', -1))
        return (ida_idp.get_reg_name(reg, 4) or '').lower() if reg >= 0 else None
    except Exception:
        return None


def signed32(value):
    value = int(value) & 0xFFFFFFFF
    return value - 0x100000000 if value & 0x80000000 else value


def is_read(ea, insn):
    mnem = (idc.print_insn_mnem(int(ea)) or '').lower()
    if mnem in ('fld', 'fild', 'flds', 'fldl', 'fimul', 'lea') or mnem.startswith('cvtsi2'):
        return True
    if mnem in ('mov', 'movzx', 'movsx', 'movss', 'movsd', 'movd'):
        return int(insn.ops[0].type) not in (
            int(idaapi.o_mem), int(idaapi.o_displ), int(idaapi.o_phrase))
    return False


def inspect_candidate(start):
    fn = ida_funcs.get_func(int(start))
    if fn is None or int(fn.start_ea) != int(start):
        return []
    events = {}
    anchors = {}
    immediates = set()
    known_bases = {}
    for ea in idautils.FuncItems(int(start)):
        insn = idautils.DecodeInstruction(int(ea))
        if not insn:
            continue
        offb = disp32_offset(insn)
        targets = set()
        for ref in idautils.DataRefsFrom(int(ea)):
            ref = int(ref)
            seg = ida_segment.getseg(ref)
            if seg is not None and ida_segment.get_segm_name(seg) in ('.got', '.got.plt'):
                pointee = int(ida_bytes.get_dword(ref))
                if is_writable_data(pointee):
                    targets.add(pointee)
            elif is_writable_data(ref):
                targets.add(ref)
        for op in insn.ops:
            if int(op.type) == int(idaapi.o_void):
                break
            if int(op.type) == int(idaapi.o_imm):
                immediates.add(int(op.value) & 0xFFFFFFFF)
            elif int(op.type) == int(idaapi.o_mem) and is_writable_data(int(op.addr)):
                targets.add(int(op.addr))
            elif int(op.type) in (int(idaapi.o_displ), int(idaapi.o_phrase)):
                base_reg = reg_name(op)
                if base_reg in known_bases:
                    value = (int(known_bases[base_reg]) + signed32(op.addr)) & 0xFFFFFFFF
                    if is_writable_data(value):
                        targets.add(value)
        for target in targets:
            event = {
                'gv_ea': int(target),
                'insn_ea': int(ea),
                'insn_len': int(insn.size),
                'insn_disasm': idc.generate_disasm_line(int(ea), 0) or '',
                'mnem': (idc.print_insn_mnem(int(ea)) or '').lower(),
                'read': is_read(ea, insn),
            }
            events.setdefault(target, []).append(event)
            if offb:
                anchor = {**event, 'insn_disp': int(offb)}
                if target not in anchors or (event['read'] and not anchors[target]['read']):
                    anchors[target] = anchor
        if int(insn.ops[0].type) == int(idaapi.o_reg):
            destination = reg_name(insn.ops[0])
            next_base = None
            mnem = (idc.print_insn_mnem(int(ea)) or '').lower()
            if mnem == 'mov' and int(insn.ops[1].type) == int(idaapi.o_reg):
                next_base = known_bases.get(reg_name(insn.ops[1]))
            elif mnem in ('mov', 'lea') and len(targets) == 1:
                next_base = next(iter(targets))
            if next_base is None:
                known_bases.pop(destination, None)
            else:
                known_bases[destination] = int(next_base)
    if not {0x600, 0xB64, 0xB66}.issubset(immediates):
        return []
    groups = []
    for base in sorted(events):
        field_events = [events.get(base + offset, []) for offset in (0, 4, 8, 12)]
        if any(not items for items in field_events) or base not in anchors:
            continue
        matched = False
        for fields in itertools.product(*field_events):
            if any(not field['read'] for field in fields):
                continue
            first_mnems = {field['mnem'] for field in fields[:3]}
            if not all(
                    mnem in {'fild', 'fimul', 'mov', 'movd', 'movzx', 'movsx'}
                    or mnem.startswith('cvtsi2')
                    for mnem in first_mnems):
                continue
            if fields[3]['mnem'] not in ('mov', 'movzx', 'movsx'):
                continue
            eas = [field['insn_ea'] for field in fields]
            if max(eas) - min(eas) <= 0xC0:
                matched = True
                break
        if matched:
            groups.append({'base': base, 'ref': anchors[base]})
    return groups


globals().update(locals())

try:
    if idaapi.inf_is_64bit():
        raise RuntimeError('expected 32-bit x86')
    owner = ida_funcs.get_func(int(OWNER_EA))
    if owner is None or int(owner.start_ea) != int(OWNER_EA):
        raise RuntimeError('render owner is not a function start')
    starts = {int(owner.start_ea)}
    for ea in idautils.FuncItems(int(owner.start_ea)):
        if (idc.print_insn_mnem(int(ea)) or '').lower() != 'call':
            continue
        for ref in idautils.CodeRefsFrom(int(ea), 0):
            fn = ida_funcs.get_func(int(ref))
            if fn is not None and int(fn.start_ea) == int(ref):
                starts.add(int(ref))
    matches = []
    for start in sorted(starts):
        for item in inspect_candidate(start):
            matches.append({'owner_ea': start, **item})
    unique = {}
    for item in matches:
        unique[(item['owner_ea'], item['base'])] = item
    if len(unique) != 1:
        result = json.dumps({
            'error': 'cshift_water fog candidate is not unique',
            'candidate_count': len(unique),
            'candidates': matches,
        })
    else:
        item = next(iter(unique.values()))
        result = json.dumps({
            'pointer_size': 4,
            'owner_ea': hex(item['owner_ea']),
            'gv_ea': hex(item['base']),
            **item['ref'],
        })
except Exception as exc:
    result = json.dumps({'error': str(exc), 'trace': traceback.format_exc()})
"""


async def preprocess_cshift_water(
    session,
    expected_outputs,
    new_binary_dir,
    platform,
    image_base,
    *,
    predecessor,
    debug=False,
):
    render_owner = await inspect_owner_artifact(session, new_binary_dir, platform, image_base, predecessor)
    if render_owner is None:
        return False
    code = LOCATE_CSHIFT_WATER_PY.replace("OWNER_EA_PLACEHOLDER", str(render_owner["owner_ea"]))
    try:
        located = parse_mcp_result(await session.call_tool("py_eval", {"code": code}))
    except Exception:  # noqa: BLE001 - MCP failures fail closed.
        return False
    if not isinstance(located, dict) or located.get("error") or located.get("pointer_size") != 4:
        if debug:
            print(f"  cshift_water: fog locator failed {located}")
        return False
    try:
        semantic_owner_ea = int(located["owner_ea"], 0)
    except (KeyError, TypeError, ValueError):
        return False
    if semantic_owner_ea == render_owner["owner_ea"]:
        semantic_owner = render_owner
    else:
        function = await _inspect_function_via_mcp(session, semantic_owner_ea, image_base, "R_SetupFrame")
        allow_across = False
        if not function or not function.get("func_sig"):
            function = await _inspect_function_via_mcp(
                session,
                semantic_owner_ea,
                image_base,
                "R_SetupFrame",
                allow_across_function_boundary=True,
            )
            allow_across = function is not None and bool(function.get("func_sig"))
        if not function or not function.get("func_sig"):
            return False
        try:
            if int(function["func_va"], 0) != semantic_owner_ea:
                return False
            semantic_owner_end = semantic_owner_ea + int(function["func_size"], 0)
        except (KeyError, TypeError, ValueError):
            return False
        semantic_owner = {
            "function": function,
            "owner_ea": semantic_owner_ea,
            "owner_end": semantic_owner_end,
            "allow_across": allow_across,
        }
    if debug:
        print(
            f"  cshift_water: owner={located.get('owner_ea')} gv={located.get('gv_ea')} "
            f"insn={located.get('insn_ea')} {located.get('insn_disasm', '')}"
        )
    return await write_located_globals(
        session,
        expected_outputs,
        platform,
        image_base,
        semantic_owner,
        {"cshift_water": located},
    )


LOCATE_CURRENTTEXTURE_PY = r"""
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


def is_writable_data(ea):
    seg = ida_segment.getseg(int(ea))
    if seg is None or int(ea) == 0:
        return False
    perms = int(getattr(seg, 'perm', 0))
    return bool(perms & int(getattr(ida_segment, 'SEGPERM_WRITE', 2))) and not bool(
        perms & int(getattr(ida_segment, 'SEGPERM_EXEC', 1)))


def reg_name(op):
    try:
        reg = int(getattr(op, 'reg', -1))
        return (ida_idp.get_reg_name(reg, 4) or '').lower() if reg >= 0 else None
    except Exception:
        return None


def signed32(value):
    value = int(value) & 0xFFFFFFFF
    return value - 0x100000000 if value & 0x80000000 else value


def disp32_offset(insn):
    for op in insn.ops:
        if int(op.type) == int(idaapi.o_void):
            break
        offb = int(getattr(op, 'offb', 0) or 0)
        if offb and int(insn.size) - offb >= 4 and int(op.type) in (
                int(idaapi.o_mem), int(idaapi.o_displ), int(idaapi.o_imm), int(idaapi.o_phrase)):
            return offb
    return 0


def is_got(ea):
    seg = ida_segment.getseg(int(ea))
    return seg is not None and ida_segment.get_segm_name(seg) in ('.got', '.got.plt')


def referenced_globals(ea, insn, known_bases):
    targets = set()
    for ref in idautils.DataRefsFrom(int(ea)):
        ref = int(ref)
        if is_got(ref):
            pointee = int(ida_bytes.get_dword(ref))
            if is_writable_data(pointee):
                targets.add(pointee)
        elif is_writable_data(ref):
            targets.add(ref)
    for op in insn.ops:
        if int(op.type) == int(idaapi.o_void):
            break
        if int(op.type) == int(idaapi.o_mem) and is_writable_data(int(op.addr)):
            targets.add(int(op.addr))
        elif int(op.type) in (int(idaapi.o_displ), int(idaapi.o_phrase)):
            base = reg_name(op)
            if base in known_bases:
                value = (int(known_bases[base]) + signed32(op.addr)) & 0xFFFFFFFF
                if is_writable_data(value):
                    targets.add(value)
    return targets


globals().update(locals())

try:
    if idaapi.inf_is_64bit():
        raise RuntimeError('expected 32-bit x86')
    owner = ida_funcs.get_func(int(OWNER_EA))
    if owner is None or int(owner.start_ea) != int(OWNER_EA):
        raise RuntimeError('GL_Bind is not a function start')
    known_bases = {}
    entries = []
    for ea in idautils.FuncItems(int(owner.start_ea)):
        insn = idautils.DecodeInstruction(int(ea))
        if not insn:
            continue
        mnem = (idc.print_insn_mnem(int(ea)) or '').lower()
        targets = referenced_globals(int(ea), insn, known_bases)
        entries.append({
            'ea': int(ea),
            'insn': insn,
            'mnem': mnem,
            'targets': targets,
            'len': int(insn.size),
            'disp': disp32_offset(insn),
            'disasm': idc.generate_disasm_line(int(ea), 0) or '',
        })
        # Address loads only: ``lea reg, [abs]`` and a PIC ``mov reg, [.got slot]``.
        if int(insn.ops[0].type) == int(idaapi.o_reg) and mnem in ('lea', 'mov'):
            destination = reg_name(insn.ops[0])
            base = None
            if mnem == 'lea':
                if len(targets) == 1 and int(insn.ops[1].type) == int(idaapi.o_displ):
                    base = next(iter(targets))
            elif int(insn.ops[1].type) in (int(idaapi.o_mem), int(idaapi.o_displ)):
                refs = [int(ref) for ref in idautils.DataRefsFrom(int(ea))]
                if any(is_got(ref) for ref in refs) and len(targets) == 1:
                    base = next(iter(targets))
            if base is None:
                known_bases.pop(destination, None)
            else:
                known_bases[destination] = base
    first = {}
    read = set()
    written = set()
    for index, entry in enumerate(entries):
        if len(entry['targets']) != 1:
            continue
        gv = next(iter(entry['targets']))
        op0 = entry['insn'].ops[0]
        mem_dest = int(op0.type) in (int(idaapi.o_mem), int(idaapi.o_displ), int(idaapi.o_phrase))
        if entry['mnem'] == 'mov' and mem_dest:
            written.add(gv)
        elif entry['mnem'] in ('mov', 'cmp', 'test', 'lea'):
            read.add(gv)
        if entry['disp'] and gv not in first:
            first[gv] = index
    # GL_Bind reads currenttexture (``if (currenttexture == texnum) return;``)
    # and writes it immediately before qglBindTexture.  g_currentpalette is the
    # only other writable global the body touches and is read later, so the
    # earliest global that is both read and written is currenttexture.
    globals().update(locals())
    candidates = []
    for gv in first:
        if gv in read and gv in written:
            candidates.append(gv)
    candidates.sort(key=lambda gv: first[gv])
    if not candidates:
        result = json.dumps({'error': 'currenttexture candidate missing'})
    else:
        gv = candidates[0]
        entry = entries[first[gv]]
        result = json.dumps({
            'pointer_size': 4,
            'owner_ea': hex(int(owner.start_ea)),
            'gv_ea': hex(gv),
            'insn_ea': hex(entry['ea']),
            'insn_len': hex(entry['len']),
            'insn_disp': hex(entry['disp']),
            'insn_disasm': entry['disasm'],
        })
except Exception as exc:
    result = json.dumps({'error': str(exc), 'trace': traceback.format_exc()})
"""


async def preprocess_currenttexture(
    session,
    expected_outputs,
    new_binary_dir,
    platform,
    image_base,
    *,
    predecessor="GL_Bind",
    debug=False,
):
    owner = await inspect_owner_artifact(session, new_binary_dir, platform, image_base, predecessor)
    if owner is None:
        if debug:
            print(f"  currenttexture: missing or invalid {predecessor} artifact")
        return False
    code = LOCATE_CURRENTTEXTURE_PY.replace("OWNER_EA_PLACEHOLDER", str(owner["owner_ea"]))
    try:
        located = parse_mcp_result(await session.call_tool("py_eval", {"code": code}))
    except Exception:  # noqa: BLE001 - MCP failures fail closed.
        return False
    if not isinstance(located, dict) or located.get("error") or located.get("pointer_size") != 4:
        if debug:
            print(f"  currenttexture: locator failed {located}")
        return False
    if debug:
        print(
            f"  currenttexture: gv={located.get('gv_ea')} insn={located.get('insn_ea')} "
            f"{located.get('insn_disasm', '')}"
        )
    return await write_located_globals(
        session,
        expected_outputs,
        platform,
        image_base,
        owner,
        {"currenttexture": located},
    )


LOCATE_TRANS_OBJECT_ALLOC_GLOBALS_PY = r"""
import ida_funcs
import ida_segment
import ida_ua
import idautils
import idc
import idaapi
import json
import traceback

OWNER_EA = OWNER_EA_PLACEHOLDER

WRITE_MNEMONICS = frozenset((
    'mov', 'add', 'sub', 'and', 'or', 'xor', 'inc', 'dec', 'shl', 'shr', 'sar', 'neg', 'not', 'imul',
))


def is_writable_data(ea):
    seg = ida_segment.getseg(int(ea))
    if seg is None or int(ea) == 0:
        return False
    perms = int(getattr(seg, 'perm', 0))
    return bool(perms & int(getattr(ida_segment, 'SEGPERM_WRITE', 2))) and not bool(
        perms & int(getattr(ida_segment, 'SEGPERM_EXEC', 4)))


def absolute_target(op):
    if int(op.type) == int(idaapi.o_mem):
        return int(op.addr) & 0xFFFFFFFF
    if int(op.type) == int(idaapi.o_displ) and int(getattr(op, 'addr', 0) or 0):
        return int(op.addr) & 0xFFFFFFFF
    return 0


try:
    function = ida_funcs.get_func(OWNER_EA)
    if function is None or int(function.start_ea) != int(OWNER_EA):
        raise ValueError('owner function not found')
    stores = []
    for ea in idautils.FuncItems(int(OWNER_EA)):
        insn = ida_ua.insn_t()
        if ida_ua.decode_insn(insn, ea) == 0:
            raise ValueError('undecodable instruction at 0x%X' % int(ea))
        if insn.get_canon_mnem() not in WRITE_MNEMONICS:
            continue
        target = absolute_target(insn.ops[0])
        if not target or not is_writable_data(target):
            continue
        offb = int(getattr(insn.ops[0], 'offb', 0) or 0)
        if offb <= 0 or offb + 4 > int(insn.size):
            continue
        stores.append({
            'gv_ea': target,
            'insn_ea': int(ea),
            'insn_len': int(insn.size),
            'insn_disp': offb,
            'insn_disasm': idc.GetDisasm(int(ea)),
        })
    if len(stores) != 2:
        result = json.dumps({'error': 'expected exactly two absolute writable stores', 'stores': stores})
    elif stores[0]['gv_ea'] == stores[1]['gv_ea']:
        result = json.dumps({'error': 'both stores target the same global', 'stores': stores})
    else:
        result = json.dumps({
            'pointer_size': 4,
            'owner_ea': hex(int(function.start_ea)),
            'transObjects': stores[0],
            'maxTransObjs': stores[1],
        })
except Exception as exc:
    result = json.dumps({'error': str(exc), 'trace': traceback.format_exc()})
"""


LOCATE_TRANS_OBJECT_COUNTER_PY = r"""
import ida_funcs
import ida_idp
import ida_segment
import ida_ua
import idautils
import idc
import idaapi
import json
import traceback

OWNER_EA = OWNER_EA_PLACEHOLDER

REGISTER_WRITES = frozenset((
    'mov', 'lea', 'pop', 'add', 'sub', 'and', 'or', 'xor', 'imul', 'shl', 'shr', 'sar',
    'inc', 'dec', 'neg', 'not', 'movzx', 'movsx',
))


def is_writable_data(ea):
    seg = ida_segment.getseg(int(ea))
    if seg is None or int(ea) == 0:
        return False
    perms = int(getattr(seg, 'perm', 0))
    return bool(perms & int(getattr(ida_segment, 'SEGPERM_WRITE', 2))) and not bool(
        perms & int(getattr(ida_segment, 'SEGPERM_EXEC', 4)))


def absolute_target(op):
    if int(op.type) == int(idaapi.o_mem):
        return int(op.addr) & 0xFFFFFFFF
    if int(op.type) == int(idaapi.o_displ) and int(getattr(op, 'addr', 0) or 0):
        return int(op.addr) & 0xFFFFFFFF
    return 0


def reg_name(op):
    try:
        index = int(getattr(op, 'reg', -1))
        return (ida_idp.get_reg_name(index, 4) or '').lower() if index >= 0 else ''
    except Exception:
        return ''


try:
    function = ida_funcs.get_func(OWNER_EA)
    if function is None or int(function.start_ea) != int(OWNER_EA):
        raise ValueError('owner function not found')
    references = {}
    candidates = []
    zero_regs = set()
    for ea in idautils.FuncItems(int(OWNER_EA)):
        insn = ida_ua.insn_t()
        if ida_ua.decode_insn(insn, ea) == 0:
            raise ValueError('undecodable instruction at 0x%X' % int(ea))
        mnem = insn.get_canon_mnem()
        op0 = insn.ops[0]
        op1 = insn.ops[1]

        for op in (op0, op1):
            target = absolute_target(op)
            if target and is_writable_data(target):
                references.setdefault(target, []).append(int(ea))

        destination = absolute_target(op0)
        if mnem in REGISTER_WRITES and destination and is_writable_data(destination):
            offb = int(getattr(op0, 'offb', 0) or 0)
            stored_zero = (
                int(op1.type) == int(idaapi.o_imm)
                and (int(op1.value) & 0xFFFFFFFF) == 0
            )
            if not stored_zero and int(op1.type) == int(idaapi.o_reg):
                name = reg_name(op1)
                stored_zero = bool(name) and name in zero_regs
            if stored_zero and offb > 0 and offb + 4 <= int(insn.size):
                candidates.append({
                    'gv_ea': destination,
                    'insn_ea': int(ea),
                    'insn_len': int(insn.size),
                    'insn_disp': offb,
                    'insn_disasm': idc.GetDisasm(int(ea)),
                })

        dst = reg_name(op0)
        if mnem in ('xor', 'sub') and dst and dst == reg_name(op1):
            zero_regs.add(dst)
        elif mnem == 'mov' and dst and int(op1.type) == int(idaapi.o_imm) and (int(op1.value) & 0xFFFFFFFF) == 0:
            zero_regs.add(dst)
        elif mnem == 'call':
            zero_regs.clear()
        elif mnem in REGISTER_WRITES and dst:
            zero_regs.discard(dst)

    unique = {}
    for candidate in candidates:
        unique.setdefault(candidate['gv_ea'], candidate)
    if len(unique) != 1:
        result = json.dumps({
            'error': 'counter global is not unique',
            'candidate_count': len(unique),
            'candidates': [
                {**item, 'gv_ea': hex(item['gv_ea']), 'insn_ea': hex(item['insn_ea'])}
                for item in unique.values()
            ],
        })
    else:
        item = next(iter(unique.values()))
        if len(references.get(item['gv_ea'], ())) < 2:
            result = json.dumps({'error': 'counter global is never read in the owner body'})
        else:
            result = json.dumps({
                'pointer_size': 4,
                'owner_ea': hex(int(function.start_ea)),
                **{key: (hex(value) if key in ('gv_ea', 'insn_ea') else value) for key, value in item.items()},
            })
except Exception as exc:
    result = json.dumps({'error': str(exc), 'trace': traceback.format_exc()})
"""


async def _locate_trans_object_globals(session, owner, code, debug, label):
    if owner is None:
        return None
    locator = code.replace("OWNER_EA_PLACEHOLDER", str(owner["owner_ea"]))
    try:
        payload = parse_mcp_result(await session.call_tool("py_eval", {"code": locator}))
    except Exception:  # noqa: BLE001 - MCP failures fail closed.
        return None
    if not isinstance(payload, dict) or payload.get("error") or payload.get("pointer_size") != 4:
        if debug:
            print(f"  {label}: locator failed {payload}")
        return None
    return payload


async def preprocess_trans_object_globals(
    session,
    expected_outputs,
    new_binary_dir,
    platform,
    image_base,
    *,
    owner_name="R_AllocTransObjects",
    counter_owner_name="R_DrawTEntitiesOnList",
    debug=False,
):
    if platform not in {"windows", "linux"}:
        return False
    owner = await inspect_owner_artifact(session, new_binary_dir, platform, image_base, owner_name)
    counter_owner = await inspect_owner_artifact(session, new_binary_dir, platform, image_base, counter_owner_name)
    if owner is None or counter_owner is None:
        if debug:
            print(f"  trans objects: missing or invalid {owner_name}/{counter_owner_name} artifact")
        return False
    allocated = await _locate_trans_object_globals(
        session, owner, LOCATE_TRANS_OBJECT_ALLOC_GLOBALS_PY, debug, "trans objects"
    )
    if allocated is None:
        return False
    if debug:
        for name in ("transObjects", "maxTransObjs"):
            print(f"  trans objects: {name}={allocated[name]['gv_ea']} {allocated[name]['insn_disasm']}")
    located = {name: allocated[name] for name in ("transObjects", "maxTransObjs")}
    if not await write_located_globals(session, expected_outputs, platform, image_base, owner, located):
        return False
    counter = await _locate_trans_object_globals(
        session, counter_owner, LOCATE_TRANS_OBJECT_COUNTER_PY, debug, "trans objects counter"
    )
    if counter is None:
        return False
    if debug:
        print(f"  trans objects: numTransObjs={counter['gv_ea']} {counter['insn_disasm']}")
    return await write_located_globals(
        session, expected_outputs, platform, image_base, counter_owner, {"numTransObjs": counter}
    )
