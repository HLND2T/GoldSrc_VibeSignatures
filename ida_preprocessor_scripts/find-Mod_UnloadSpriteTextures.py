#!/usr/bin/env python3
"""Locate the HUD-sprite shutdown graph and its list globals.

``SPR_Load`` owns a stable allocation-failure string and accesses both
``gSpriteList`` and ``gSpriteCount``. The sprite-texture-name helper owns the
``%s_%i`` format (and is inlined into newer builds); its owner/callers are
filtered by distinctive model/sprite member offsets. Starting from those
anchors, the locator finds the
unique ``SPR_Shutdown -> Mod_UnloadSpriteTextures`` caller edge, intersects
SPR_Shutdown's cleared globals with SPR_Load's globals, and classifies the pair
through SPR_Init's ``256 * sizeof(SPRITELIST) == 0xC00`` allocation shape.

Discovery supports PE absolute operands, relocated ELF absolute operands, and
SvEngine Linux EBX/GOTOFF operands. Generated signatures validate the located
outputs but never participate in discovery.
"""

from pathlib import Path

from ida_analyze_util import (
    _inspect_function_via_mcp,
    _output_for_symbol,
    gv_resolution_fields_via_mcp,
    parse_mcp_result,
    write_func_yaml,
    write_gv_yaml,
)

TARGET_FUNCTIONS = ("SPR_Shutdown", "Mod_UnloadSpriteTextures")
TARGET_GLOBALS = ("gSpriteList", "gSpriteCount")
SPR_LOAD_ERROR = "cannot allocate more than %d HUD sprites\n"
SPRITE_TEXTURE_FORMAT = "%s_%i"

LOCATE_PY = r"""
import collections
import ida_bytes
import ida_funcs
import ida_idp
import ida_segment
import idaapi
import idautils
import idc
import json
import traceback

SPR_LOAD_ERROR = SPR_LOAD_ERROR_PLACEHOLDER
SPRITE_TEXTURE_FORMAT = SPRITE_TEXTURE_FORMAT_PLACEHOLDER
MODEL_OFFSETS = {0x44, 0x40, 0x184, 0x0C}


def is_mapped(ea):
    return int(ea) != 0 and ida_segment.getseg(int(ea)) is not None


def is_writable_data(ea):
    seg = ida_segment.getseg(int(ea))
    if seg is None or int(ea) == 0:
        return False
    perms = int(getattr(seg, 'perm', 0))
    writable = int(getattr(ida_segment, 'SEGPERM_WRITE', 2))
    executable = int(getattr(ida_segment, 'SEGPERM_EXEC', 4))
    return bool(perms & writable) and not bool(perms & executable)


def reg_name(op):
    try:
        return (ida_idp.get_reg_name(int(op.reg), 4) or '').lower()
    except Exception:
        return ''


def pic_anchor(func_start):
    # Recover the SvEngine EBX base from get-PC-thunk; add ebx, imm32.
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


def operand_target(ea, op, pic_base):
    op_type = int(op.type)
    if op_type == int(idaapi.o_mem):
        value = int(op.addr) & 0xFFFFFFFF
        return value if is_mapped(value) else None
    if op_type == int(idaapi.o_imm):
        value = int(op.value) & 0xFFFFFFFF
        return value if is_mapped(value) else None
    if op_type != int(idaapi.o_displ) or pic_base is None or reg_name(op) != 'ebx':
        return None
    insn = idautils.DecodeInstruction(int(ea))
    raw = ida_bytes.get_bytes(int(ea), int(insn.size)) if insn else None
    off = int(getattr(op, 'offb', 0) or 0)
    if not raw or off <= 0 or off + 4 > len(raw):
        return None
    disp = int.from_bytes(raw[off:off + 4], 'little', signed=True)
    value = (int(pic_base) + disp) & 0xFFFFFFFF
    return value if is_mapped(value) else None


def instruction_accesses(ea, pic_base, writable_only=False):
    insn = idautils.DecodeInstruction(int(ea))
    if not insn:
        return []
    accesses = []
    seen = set()
    for index, op in enumerate(insn.ops):
        if int(op.type) == int(idaapi.o_void):
            break
        target = operand_target(ea, op, pic_base)
        if target is None or (writable_only and not is_writable_data(target)):
            continue
        key = (target, index)
        if key in seen:
            continue
        seen.add(key)
        accesses.append({
            'target': int(target),
            'operand': int(index),
            'disp': int(getattr(op, 'offb', 0) or 0),
            'length': int(insn.size),
        })
    # Several early PE databases retain the encoded operand without its xref.
    for target in idautils.DataRefsFrom(int(ea)):
        target = int(target)
        if not is_mapped(target) or (writable_only and not is_writable_data(target)):
            continue
        if all(item['target'] != target for item in accesses):
            accesses.append({'target': target, 'operand': -1, 'disp': 0, 'length': int(insn.size)})
    return accesses


def exact_string_addresses(text, case_insensitive=False):
    expected = text.casefold() if case_insensitive else text
    return {
        int(item.ea)
        for item in idautils.Strings()
        if (str(item).casefold() if case_insensitive else str(item)) == expected
    }


def recover_orphan_owner(ea):
    owner = ida_funcs.get_func(int(ea))
    if owner is not None:
        return owner
    previous = ida_funcs.get_prev_func(int(ea))
    segment = ida_segment.getseg(int(ea))
    if previous is None or segment is None:
        return None
    cursor = ida_bytes.next_head(int(previous.end_ea) - 1, int(ea) + 1)
    while cursor != idaapi.BADADDR and cursor <= int(ea):
        if cursor - int(previous.end_ea) > 0x40:
            return None
        mnem = (idc.print_insn_mnem(int(cursor)) or '').lower()
        if mnem not in ('int3', 'nop', ''):
            break
        cursor = ida_bytes.next_head(int(cursor), int(ea) + 1)
    if cursor == idaapi.BADADDR or cursor > int(ea) or int(ea) - int(cursor) > 0x800:
        return None
    if not ida_funcs.add_func(int(cursor), idaapi.BADADDR):
        return None
    owner = ida_funcs.get_func(int(ea))
    return owner if owner is not None and int(owner.start_ea) == int(cursor) else None


def owner_functions_for_strings(addresses):
    owners = set()
    for address in addresses:
        for xref in idautils.XrefsTo(int(address), 0):
            func = recover_orphan_owner(int(xref.frm))
            if func is not None:
                owners.add(int(func.start_ea))
    if owners:
        return owners
    # Decode operands too because some early PE IDBs lack push-immediate xrefs.
    for start in idautils.Functions():
        start = int(start)
        func = ida_funcs.get_func(start)
        if func is None:
            continue
        base = pic_anchor(start)
        for ea in idautils.FuncItems(start):
            if any(item['target'] in addresses for item in instruction_accesses(ea, base)):
                owners.add(start)
                break
    return owners


def common_global_owner_functions(targets):
    owner_sets = []
    for target in targets:
        owners = set()
        for xref in idautils.XrefsTo(int(target), 0):
            func = ida_funcs.get_func(int(xref.frm))
            if func is not None:
                owners.add(int(func.start_ea))
        if not owners:
            return set()
        owner_sets.append(owners)
    return set.intersection(*owner_sets)


def function_size(start):
    func = ida_funcs.get_func(int(start))
    return 0 if func is None else int(func.end_ea) - int(func.start_ea)


def member_offsets(start):
    values = set()
    for ea in idautils.FuncItems(int(start)):
        insn = idautils.DecodeInstruction(int(ea))
        if not insn:
            continue
        for op in insn.ops:
            if int(op.type) == int(idaapi.o_void):
                break
            if int(op.type) == int(idaapi.o_displ):
                values.add(int(op.addr) & 0xFFFFFFFF)
    return values


def normalize_function(start):
    current = int(start)
    seen = set()
    for _ in range(4):
        if current in seen:
            return None
        seen.add(current)
        func = ida_funcs.get_func(current)
        if func is None:
            return None
        current = int(func.start_ea)
        if not (int(func.flags) & int(ida_funcs.FUNC_THUNK)):
            return current
        target = ida_funcs.calc_thunk_func_target(func)
        if isinstance(target, (tuple, list)):
            target = target[0] if target else idaapi.BADADDR
        try:
            target = int(target)
        except (TypeError, ValueError):
            return None
        if target == int(idaapi.BADADDR):
            return current
        target_func = ida_funcs.get_func(target)
        if target_func is None:
            # Import thunks such as Windows free have no internal body. Their
            # thunk entry is still the stable semantic call target for counts.
            return current
        current = int(target_func.start_ea)
    return None


def direct_call_target(ea):
    if (idc.print_insn_mnem(int(ea)) or '').lower() != 'call':
        return None
    targets = set()
    for xref in idautils.XrefsFrom(int(ea), 0):
        if int(xref.type) in (int(idaapi.fl_CN), int(idaapi.fl_CF)):
            func = ida_funcs.get_func(int(xref.to))
            if func is not None:
                targets.add(int(func.start_ea))
    if len(targets) != 1:
        return None
    return next(iter(targets))


def normalized_call_targets(start):
    targets = []
    for ea in idautils.FuncItems(int(start)):
        direct = direct_call_target(ea)
        if direct is None:
            continue
        normalized = normalize_function(direct)
        if normalized is not None:
            targets.append((int(ea), int(direct), int(normalized)))
    return targets


def normalized_callers(target):
    aliases = {int(target)}
    for start in idautils.Functions():
        func = ida_funcs.get_func(int(start))
        if func is None or not (int(func.flags) & int(ida_funcs.FUNC_THUNK)):
            continue
        if normalize_function(int(start)) == int(target):
            aliases.add(int(start))
    callers = set()
    sites = []
    for alias in aliases:
        for xref in idautils.XrefsTo(alias, 0):
            if int(xref.type) not in (int(idaapi.fl_CN), int(idaapi.fl_CF)):
                continue
            owner = ida_funcs.get_func(int(xref.frm))
            if owner is None:
                continue
            owner_start = int(owner.start_ea)
            if owner_start in aliases or (int(owner.flags) & int(ida_funcs.FUNC_THUNK)):
                continue
            callers.add(owner_start)
            sites.append((int(xref.frm), owner_start, alias))
    return callers, sites, aliases


def has_stride_twelve(start):
    direct = False
    lea_times_two = False
    shift_by_two = False
    for ea in idautils.FuncItems(int(start)):
        insn = idautils.DecodeInstruction(int(ea))
        if not insn:
            continue
        mnem = (idc.print_insn_mnem(int(ea)) or '').lower()
        for op in insn.ops:
            if int(op.type) == int(idaapi.o_void):
                break
            if int(op.type) == int(idaapi.o_imm) and int(op.value) == 12 and mnem in ('add', 'imul'):
                direct = True
        line = (idc.generate_disasm_line(int(ea), 0) or '').replace(' ', '').lower()
        if mnem == 'lea' and '*2' in line:
            lea_times_two = True
        if mnem == 'shl' and any(
            int(op.type) == int(idaapi.o_imm) and int(op.value) == 2 for op in insn.ops
        ):
            shift_by_two = True
    return direct or (lea_times_two and shift_by_two)


def shutdown_context(mod):
    callers, callsites, aliases = normalized_callers(mod)
    if len(callers) != 1:
        return None
    spr_shutdown = next(iter(callers))
    calls = normalized_call_targets(spr_shutdown)
    counts = collections.Counter(target for _, _, target in calls)
    repeated = [target for target, count in counts.items() if target != mod and count >= 2]
    if (
        counts.get(mod) != 1
        or len(repeated) != 1
        or function_size(spr_shutdown) < 0x50
        or not has_stride_twelve(spr_shutdown)
    ):
        return None
    return {
        'SPR_Shutdown': spr_shutdown,
        'callsites': callsites,
        'aliases': aliases,
        'free_helper': repeated[0],
    }


def function_access_records(start):
    base = pic_anchor(int(start))
    records = []
    for ea in idautils.FuncItems(int(start)):
        insn = idautils.DecodeInstruction(int(ea))
        if not insn:
            continue
        mnem = (idc.print_insn_mnem(int(ea)) or '').lower()
        accesses = instruction_accesses(ea, base, writable_only=True)
        store_target = None
        if mnem == 'mov' and int(insn.ops[0].type) in (int(idaapi.o_mem), int(idaapi.o_displ)):
            store_target = operand_target(ea, insn.ops[0], base)
        for access in accesses:
            records.append({
                **access,
                'ea': int(ea),
                'mnem': mnem,
                'store': store_target == access['target'],
            })
    return records


def immediate_values(start):
    values = set()
    for ea in idautils.FuncItems(int(start)):
        insn = idautils.DecodeInstruction(int(ea))
        if not insn:
            continue
        for op in insn.ops:
            if int(op.type) == int(idaapi.o_void):
                break
            if int(op.type) == int(idaapi.o_imm):
                values.add(int(op.value) & 0xFFFFFFFF)
    return values


def count_init_stores(start, candidates):
    base = pic_anchor(int(start))
    stores = set()
    constants = {}
    for ea in idautils.FuncItems(int(start)):
        insn = idautils.DecodeInstruction(int(ea))
        if not insn:
            continue
        mnem = (idc.print_insn_mnem(int(ea)) or '').lower()
        destination, source = insn.ops[0], insn.ops[1]
        if mnem == 'mov' and int(destination.type) in (int(idaapi.o_mem), int(idaapi.o_displ)):
            value = None
            if int(source.type) == int(idaapi.o_imm):
                value = int(source.value) & 0xFFFFFFFF
            elif int(source.type) == int(idaapi.o_reg):
                value = constants.get(reg_name(source))
            target = operand_target(ea, destination, base)
            if target in candidates and value == 0x100:
                stores.add(int(target))
        if int(destination.type) == int(idaapi.o_reg):
            name = reg_name(destination)
            constants.pop(name, None)
            if mnem == 'mov' and int(source.type) == int(idaapi.o_imm):
                constants[name] = int(source.value) & 0xFFFFFFFF
            elif mnem == 'xor' and int(source.type) == int(idaapi.o_reg) and reg_name(source) == name:
                constants[name] = 0
        if mnem == 'call':
            for name in ('eax', 'ecx', 'edx'):
                constants.pop(name, None)
    return stores


def hex_record(record):
    return {
        key: (hex(value) if isinstance(value, int) and key not in ('length', 'disp', 'operand') else value)
        for key, value in record.items()
    }


globals().update(locals())

try:
    if idaapi.inf_is_64bit():
        raise RuntimeError('expected 32-bit x86')

    # SvEngine capitalizes the first letter; the full literal is otherwise
    # byte-for-byte identical across the supported engine families.
    load_strings = exact_string_addresses(SPR_LOAD_ERROR, case_insensitive=True)
    texture_strings = exact_string_addresses(SPRITE_TEXTURE_FORMAT)
    if len(load_strings) != 1:
        raise RuntimeError(f'SPR_Load anchor string count is {len(load_strings)}, expected 1')
    if not texture_strings:
        raise RuntimeError('sprite texture format string is missing')

    load_owners = owner_functions_for_strings(load_strings)
    texture_owners = owner_functions_for_strings(texture_strings)
    if len(load_owners) != 1:
        raise RuntimeError(f'SPR_Load owner count is {len(load_owners)}, expected 1')
    spr_load = next(iter(load_owners))

    texture_context = set(texture_owners)
    for owner in texture_owners:
        owner_callers, _, _ = normalized_callers(owner)
        texture_context.update(owner_callers)
    mod_candidates = []
    for start in sorted(texture_context):
        offsets = member_offsets(start)
        calls = normalized_call_targets(start)
        context = shutdown_context(start)
        if (
            function_size(start) >= 60
            and MODEL_OFFSETS.issubset(offsets)
            and len(calls) >= 2
            and context is not None
        ):
            mod_candidates.append({
                'start': int(start),
                'size': function_size(start),
                'offsets': sorted(offsets & MODEL_OFFSETS),
                'calls': calls,
                'shutdown': context,
            })
    if len(mod_candidates) != 1:
        raise RuntimeError(f'Mod_UnloadSpriteTextures candidate count is {len(mod_candidates)}, expected 1')
    mod = int(mod_candidates[0]['start'])
    context = mod_candidates[0]['shutdown']
    spr_shutdown = int(context['SPR_Shutdown'])
    callsites = context['callsites']
    aliases = context['aliases']

    load_records = function_access_records(spr_load)
    shutdown_records = function_access_records(spr_shutdown)
    load_globals = {record['target'] for record in load_records}
    shutdown_stores = {record['target'] for record in shutdown_records if record['store']}
    sprite_globals = load_globals & shutdown_stores
    if len(sprite_globals) != 2:
        raise RuntimeError(f'sprite global intersection count is {len(sprite_globals)}, expected 2')

    init_candidates = []
    count_targets = set()
    for start in sorted(common_global_owner_functions(sprite_globals)):
        start = int(start)
        values = immediate_values(start)
        # Optimized builds pass 0xC00 directly; the CoF debug build computes
        # the same size as gSpriteCount (0x100) multiplied by the 12-byte
        # SPRITELIST stride.
        if 0xC00 not in values and 12 not in values:
            continue
        records = function_access_records(start)
        referenced = {record['target'] for record in records}
        if not sprite_globals.issubset(referenced):
            continue
        stores = count_init_stores(start, sprite_globals)
        if len(stores) == 1:
            init_candidates.append(start)
            count_targets.update(stores)
    if len(init_candidates) != 1 or len(count_targets) != 1:
        raise RuntimeError(
            f'SPR_Init classification failed: funcs={len(init_candidates)} count_targets={len(count_targets)}'
        )
    sprite_count = next(iter(count_targets))
    sprite_list = next(iter(sprite_globals - {sprite_count}))

    accesses = {}
    for name, target in (('gSpriteList', sprite_list), ('gSpriteCount', sprite_count)):
        candidates = [
            record for record in shutdown_records
            if record['target'] == target and record['disp'] > 0 and record['disp'] + 4 <= record['length']
        ]
        if not candidates:
            raise RuntimeError(f'{name} has no encodable access in SPR_Shutdown')
        accesses[name] = min(candidates, key=lambda record: record['ea'])

    result = json.dumps({
        'pointer_size': 4,
        'SPR_Load': hex(spr_load),
        'SPR_Init': hex(init_candidates[0]),
        'SPR_Shutdown': hex(spr_shutdown),
        'SPR_Shutdown_size': hex(function_size(spr_shutdown)),
        'Mod_UnloadSpriteTextures': hex(mod),
        'Mod_UnloadSpriteTextures_size': hex(function_size(mod)),
        'gSpriteList': hex(sprite_list),
        'gSpriteCount': hex(sprite_count),
        'gSpriteList_access': hex_record(accesses['gSpriteList']),
        'gSpriteCount_access': hex_record(accesses['gSpriteCount']),
        'normalized_mod_aliases': [hex(value) for value in sorted(aliases)],
        'normalized_mod_callsites': [
            {'site': hex(site), 'owner': hex(owner), 'alias': hex(alias)}
            for site, owner, alias in callsites
        ],
        'free_helper': hex(context['free_helper']),
    })
except Exception as exc:
    result = json.dumps({'error': str(exc), 'trace': traceback.format_exc()})
"""


def _outputs(expected_outputs):
    outputs = {name: _output_for_symbol(expected_outputs, name) for name in (*TARGET_FUNCTIONS, *TARGET_GLOBALS)}
    return outputs if all(outputs.values()) else None


async def _locate(session):
    code = LOCATE_PY.replace("SPR_LOAD_ERROR_PLACEHOLDER", repr(SPR_LOAD_ERROR)).replace(
        "SPRITE_TEXTURE_FORMAT_PLACEHOLDER", repr(SPRITE_TEXTURE_FORMAT)
    )
    try:
        payload = parse_mcp_result(await session.call_tool("py_eval", {"code": code}))
    except Exception:  # noqa: BLE001 - MCP failures fail closed.
        return None
    return payload if isinstance(payload, dict) else None


async def _inspect_named_function(session, ea, image_base, name):
    function = await _inspect_function_via_mcp(session, ea, image_base, name)
    allow_across = False
    if not function or not function.get("func_sig"):
        function = await _inspect_function_via_mcp(
            session,
            ea,
            image_base,
            name,
            allow_across_function_boundary=True,
        )
        allow_across = True
    if not function or not function.get("func_sig"):
        return None
    try:
        if int(function["func_va"], 0) != int(ea):
            return None
    except (KeyError, TypeError, ValueError):
        return None
    payload = {
        "func_name": name,
        "func_va": function["func_va"],
        "func_rva": function["func_rva"],
        "func_size": function["func_size"],
        "func_sig": function["func_sig"],
    }
    if allow_across:
        payload["func_sig_allow_across_function_boundary"] = True
    return payload


def _parse_int(value):
    return int(value, 0) if isinstance(value, str) else int(value)


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
    del old_yaml_map, new_binary_dir
    if platform not in {"windows", "linux"}:
        return False
    outputs = _outputs(expected_outputs)
    if outputs is None:
        if debug:
            print(f"  {skill_name}: missing one or more required outputs")
        return False

    located = await _locate(session)
    if located is None or located.get("error") or located.get("pointer_size") != 4:
        if debug:
            print(f"  {skill_name}: locator failed {located}")
        return False

    try:
        spr_ea = _parse_int(located["SPR_Shutdown"])
        mod_ea = _parse_int(located["Mod_UnloadSpriteTextures"])
        list_ea = _parse_int(located["gSpriteList"])
        count_ea = _parse_int(located["gSpriteCount"])
    except (KeyError, TypeError, ValueError):
        return False
    if min(spr_ea, mod_ea, list_ea, count_ea) < int(image_base):
        return False

    functions = {}
    for name, ea in (("SPR_Shutdown", spr_ea), ("Mod_UnloadSpriteTextures", mod_ea)):
        payload = await _inspect_named_function(session, ea, image_base, name)
        if payload is None:
            if debug:
                print(f"  {skill_name}: failed to inspect {name} at {hex(ea)}")
            return False
        functions[name] = payload

    spr_signature = functions["SPR_Shutdown"]
    globals_payload = {}
    for name, gv_ea in (("gSpriteList", list_ea), ("gSpriteCount", count_ea)):
        access = located.get(f"{name}_access")
        if not isinstance(access, dict):
            return False
        try:
            insn_ea = _parse_int(access["ea"])
            insn_length = _parse_int(access["length"])
            insn_disp = _parse_int(access["disp"])
        except (KeyError, TypeError, ValueError):
            return False
        spr_size = _parse_int(functions["SPR_Shutdown"]["func_size"])
        if not (spr_ea <= insn_ea < spr_ea + spr_size):
            return False
        resolution = await gv_resolution_fields_via_mcp(session, insn_ea, insn_disp, gv_ea, image_base, platform)
        if resolution is None:
            return False
        payload = {
            "gv_name": name,
            "gv_va": hex(gv_ea),
            "gv_rva": hex(gv_ea - int(image_base)),
            "gv_sig": spr_signature["func_sig"],
            "gv_sig_va": spr_signature["func_va"],
            "gv_inst_offset": hex(insn_ea - spr_ea),
            "gv_inst_length": hex(insn_length),
            "gv_inst_disp": hex(insn_disp),
            **resolution,
        }
        if spr_signature.get("func_sig_allow_across_function_boundary"):
            payload["gv_sig_allow_across_function_boundary"] = True
        globals_payload[name] = payload

    if debug:
        print(
            f"  {skill_name}: SPR_Shutdown={hex(spr_ea)} Mod_UnloadSpriteTextures={hex(mod_ea)} "
            f"gSpriteList={hex(list_ea)} gSpriteCount={hex(count_ea)} "
            f"SPR_Load={located.get('SPR_Load')} SPR_Init={located.get('SPR_Init')}"
        )

    for name in TARGET_FUNCTIONS:
        write_func_yaml(Path(outputs[name]), functions[name])
    for name in TARGET_GLOBALS:
        write_gv_yaml(Path(outputs[name]), globals_payload[name])
    return True
