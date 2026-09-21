#!/usr/bin/env python3
"""Locate R_StudioSetupSkin and GL_UnloadTexture.

engine/r_studio.c compares the studio texture name with ``DM_Base.bmp`` only
inside R_StudioSetupSkin (the MetaHook hit). That literal is unique in every
configured engine image. On GCC Linux the string lives in the outlined
``.part.N`` body, which is the callable MetaHook recovers; the 33/41-byte
exported wrapper only tests STUDIO_NF_CHROME and tail-jumps into it.

The same body snprintfs ``"%s%d"`` into a stack name buffer and then calls
``GL_UnloadTexture(name)`` with that buffer as its only argument, immediately
before ``GL_LoadTexture``. Discovery never uses a previous artifact signature.
"""

from ida_analyze_util import _output_for_symbol, write_func_yaml
from ida_preprocessor_scripts._engine_private_globals_common import (
    inspect_func,
    run_walk,
)

SKIN_NAME = "R_StudioSetupSkin"
UNLOAD_NAME = "GL_UnloadTexture"
DM_BASE = "DM_Base.bmp"
NAME_FORMAT = "%s%d"

WALK = r"""
import ida_frame
import ida_ua

owner = exact_string_owner(values['dm_base'])
if owner is None:
    result = {'error': 'DM_Base.bmp has no single owning function'}
else:
    strings = idautils.Strings(default_setup=False)
    strings.setup(strtypes=[ida_nalt.STRTYPE_C], minlen=4)
    format_eas = [int(item.ea) for item in strings if str(item) == values['name_format']]
    uses = []
    for string_ea in format_eas:
        for xref in idautils.XrefsTo(string_ea, 0):
            function = ida_funcs.get_func(int(xref.frm))
            if function is not None and int(function.start_ea) == int(owner):
                uses.append(int(xref.frm))
    function = ida_funcs.get_func(int(owner))
    if function is None or not uses:
        result = {'error': 'R_StudioSetupSkin does not reference the name format'}
    else:
        items = list(idautils.FuncItems(int(owner)))
        code = []
        for pc in items:
            insn = ida_ua.insn_t()
            if ida_ua.decode_insn(insn, int(pc)) <= 0:
                continue
            sp = int(ida_frame.get_spd(function, int(pc)))
            ops = []
            for index, op in enumerate(insn.ops):
                if int(op.type) == int(idaapi.o_void):
                    break
                kind = int(op.type)
                if kind == int(idaapi.o_imm):
                    ops.append(('imm', int(op.value) & 0xFFFFFFFF))
                    continue
                if kind in (int(idaapi.o_near), int(idaapi.o_far)):
                    ops.append(('imm', int(idc.get_operand_value(int(pc), index)) & 0xFFFFFFFF))
                    continue
                if kind == int(idaapi.o_reg) and int(ida_ua.get_dtype_size(op.dtype)) == 4:
                    ops.append(('reg', (ida_idp.get_reg_name(int(op.reg), 4) or '').lower()))
                    continue
                if kind in (int(idaapi.o_displ), int(idaapi.o_phrase)):
                    base = reg4(op)
                    disp = signed32(op.addr) if kind == int(idaapi.o_displ) else 0
                    if base == 'esp':
                        ops.append(('esp', int(sp) + int(disp)))
                    elif base == 'ebp':
                        ops.append(('ebp', int(disp)))
                    else:
                        ops.append(('other', None))
                    continue
                ops.append(('other', None))
            code.append({
                'ea': int(pc),
                'mnem': (idc.print_insn_mnem(int(pc)) or '').lower(),
                'ops': ops,
                'sp': sp,
            })
        by_ea = {entry['ea']: index for index, entry in enumerate(code)}
        snprintf_indexes = []
        for use in uses:
            start = by_ea.get(use)
            if start is None:
                continue
            for index in range(start, len(code)):
                if code[index]['mnem'] == 'call':
                    snprintf_indexes.append(index)
                    break
        if len(set(snprintf_indexes)) != 1:
            result = {'error': 'snprintf of name format is not unique: %s' % (snprintf_indexes,)}
        else:
            caller_saved = {'eax', 'ecx', 'edx'}

            def load_slot(index, slot):
                for previous in range(index - 1, -1, -1):
                    entry = code[previous]
                    ops = entry['ops']
                    if entry['mnem'] == 'mov' and len(ops) > 1 and ops[0] == slot:
                        return eval_value(previous, ops[1])
                return None

            def eval_reg(index, name):
                for previous in range(index - 1, -1, -1):
                    entry = code[previous]
                    ops = entry['ops']
                    mnem = entry['mnem']
                    if mnem == 'call' and name in caller_saved:
                        return None
                    if not ops or ops[0] != ('reg', name):
                        continue
                    if mnem == 'lea' and len(ops) > 1 and ops[1][0] in ('esp', 'ebp'):
                        return ops[1]
                    if mnem == 'mov' and len(ops) > 1:
                        source = ops[1]
                        if source[0] == 'imm':
                            return source
                        if source[0] == 'reg':
                            return eval_reg(previous, source[1])
                        if source[0] in ('esp', 'ebp'):
                            return load_slot(previous, source)
                        return None
                    if mnem in ('cmp', 'test'):
                        continue
                    return None
                return None

            def eval_value(index, operand):
                if operand is None:
                    return None
                if operand[0] in ('imm', 'esp', 'ebp'):
                    return operand
                if operand[0] == 'reg':
                    return eval_reg(index, operand[1])
                return None

            def arg0(index):
                call_sp = code[index]['sp']
                for previous in range(index - 1, -1, -1):
                    entry = code[previous]
                    mnem = entry['mnem']
                    ops = entry['ops']
                    if mnem == 'call':
                        return None
                    if mnem == 'push' and ops:
                        return eval_value(previous, ops[0])
                    if mnem == 'mov' and len(ops) > 1 and ops[0] == ('esp', call_sp):
                        return eval_value(previous, ops[1])
                return None

            snprintf_index = snprintf_indexes[0]
            dest = arg0(snprintf_index)
            if dest is None or dest[0] not in ('esp', 'ebp'):
                result = {'error': 'snprintf dest is not a stack name buffer: %s' % (dest,)}
            else:
                unload = None
                site = None
                for index in range(snprintf_index + 1, len(code)):
                    if code[index]['mnem'] != 'call':
                        continue
                    if arg0(index) != dest:
                        continue
                    target = local_call_target(code[index]['ea'])
                    if target is None or target == int(owner):
                        continue
                    unload = target
                    site = code[index]['ea']
                    break
                if unload is None:
                    result = {'error': 'no 1-arg name-buffer call after snprintf'}
                else:
                    result = {
                        'pointer_size': 4,
                        'owner_ea': hex(int(owner)),
                        'unload_ea': hex(int(unload)),
                        'snprintf_ea': hex(code[snprintf_index]['ea']),
                        'unload_site': hex(int(site)),
                    }
"""


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
    _ = old_yaml_map, new_binary_dir
    skin_output = _output_for_symbol(expected_outputs, SKIN_NAME)
    unload_output = _output_for_symbol(expected_outputs, UNLOAD_NAME)
    if skin_output is None or unload_output is None:
        return False

    located = await run_walk(session, WALK, {"dm_base": DM_BASE, "name_format": NAME_FORMAT})
    if located.get("error") or located.get("pointer_size") != 4:
        if debug:
            print(f"{skill_name}: {located.get('error')}")
        return False
    try:
        owner_ea = int(located["owner_ea"], 0)
        unload_ea = int(located["unload_ea"], 0)
    except (TypeError, ValueError):
        return False
    if owner_ea == unload_ea:
        if debug:
            print(f"{skill_name}: GL_UnloadTexture collapsed onto R_StudioSetupSkin")
        return False

    skin = await inspect_func(session, owner_ea, image_base, SKIN_NAME)
    unload = await inspect_func(session, unload_ea, image_base, UNLOAD_NAME)
    if not skin or not unload:
        if debug:
            print(f"{skill_name}: inspect failed skin={owner_ea:#x} unload={unload_ea:#x}")
        return False
    if int(skin["func_va"], 0) != owner_ea or int(unload["func_va"], 0) != unload_ea:
        return False

    write_func_yaml(skin_output, skin)
    write_func_yaml(unload_output, unload)
    if debug:
        print(
            f"{skill_name}: {SKIN_NAME}={owner_ea:#x} {UNLOAD_NAME}={unload_ea:#x} "
            f"snprintf={located.get('snprintf_ea')} site={located.get('unload_site')}"
        )
    return True
