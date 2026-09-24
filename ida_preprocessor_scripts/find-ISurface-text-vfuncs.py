#!/usr/bin/env python3
"""Derive vgui2::ISurface text slots from the two verified draw callbacks.

Both callbacks repeatedly obtain the same ISurface interface. Pair each such
getter call with its following virtual call in the same basic block. Their
shared font/position/color prefix, iswprint split, common final ABC query, and
the concrete BaseUISurface flush forwarder disambiguate the source roles.
No platform-specific vtable index is used for discovery.
"""

from pathlib import Path

from ida_analyze_util import _load_yaml_mapping, _output_for_symbol, write_func_yaml
from ida_preprocessor_scripts._engine_private_globals_common import run_walk


SOURCE_SEQUENCE_LENGTH = 6

LOCATE = r"""
import ida_gdl

CHAR = int(values['char'])
ADD = int(values['add'])
VTABLE = {int(k): int(v, 0) for k, v in values['vtable'].items()}
EXPECTED = int(values['sequence_length'])

def owner(ea):
    fn = ida_funcs.get_func(int(ea))
    return fn if fn is not None and int(fn.start_ea) == int(ea) else None

def calls_and_blocks(start):
    fn = owner(start)
    if fn is None:
        return None, None
    blocks = list(ida_gdl.FlowChart(fn))
    direct = {}
    for ea in idautils.FuncItems(start):
        if (idc.print_insn_mnem(int(ea)) or '').lower() != 'call':
            continue
        insn = idautils.DecodeInstruction(int(ea))
        if insn and int(insn.ops[0].type) == int(idaapi.o_near):
            target = local_call_target(int(ea))
            if target is not None:
                direct.setdefault(target, []).append(int(ea))
    return direct, blocks

def getter_events(start, getter, blocks):
    events = []
    for ea in idautils.FuncItems(start):
        if (idc.print_insn_mnem(int(ea)) or '').lower() != 'call':
            continue
        if local_call_target(int(ea)) != getter:
            continue
        block = next((item for item in blocks if item.start_ea <= ea < item.end_ea), None)
        if block is None:
            return None
        following = int(ea) + int(idautils.DecodeInstruction(int(ea)).size)
        virtual = []
        for cursor in idautils.Heads(following, int(block.end_ea)):
            if (idc.print_insn_mnem(int(cursor)) or '').lower() != 'call':
                continue
            insn = idautils.DecodeInstruction(int(cursor))
            if insn is None or int(insn.ops[0].type) != int(idaapi.o_displ):
                break
            offset = int(insn.ops[0].addr) & 0xFFFFFFFF
            if offset % 4 == 0:
                virtual.append((int(cursor), offset // 4))
            break
        if len(virtual) != 1:
            return None
        events.append((int(ea), virtual[0][0], virtual[0][1]))
    return sorted(events)

char_calls, char_blocks = calls_and_blocks(CHAR)
add_calls, add_blocks = calls_and_blocks(ADD)
if char_calls is None or add_calls is None:
    result = {'error': 'draw callback is not a function start'}
else:
    candidates = [
        target for target in set(char_calls) & set(add_calls)
        if len(char_calls[target]) >= EXPECTED and len(add_calls[target]) >= EXPECTED
    ]
    if len(candidates) != 1:
        result = {'error': 'shared surface getter is not unique', 'candidates': [hex(x) for x in candidates]}
    else:
        getter = candidates[0]
        char_events = getter_events(CHAR, getter, char_blocks)
        add_events = getter_events(ADD, getter, add_blocks)
        if char_events is None or add_events is None or len(char_events) != EXPECTED or len(add_events) != EXPECTED:
            result = {'error': 'surface getter-to-vcall chain is incomplete'}
        else:
            a = [event[2] for event in char_events]
            b = [event[2] for event in add_events]
            printable = {}
            for label, start in (('char', CHAR), ('add', ADD)):
                refs = []
                for ea in idautils.FuncItems(start):
                    if (idc.print_insn_mnem(int(ea)) or '').lower() != 'call':
                        continue
                    if 'iswprint' in (idc.print_operand(int(ea), 0) or '').lower():
                        refs.append(int(ea))
                printable[label] = refs
            shared_prefix = a[:3] == b[:3] and len(set(a[:3])) == 3
            widths = a[-1] == b[-1]
            branches = (
                len(printable['char']) == len(printable['add']) == 1
                and char_events[2][1] < printable['char'][0] < char_events[3][1]
                and add_events[2][1] < printable['add'][0] < add_events[3][1]
            )
            expected_slots = [*a[:3], a[3], b[3], a[4], a[-1]]
            valid_entries = (
                len(set(expected_slots)) == len(expected_slots)
                and all(index in VTABLE and owner(VTABLE[index]) is not None for index in expected_slots)
            )
            flush = VTABLE.get(a[4], 0)
            forward = []
            this_member = False
            if owner(flush):
                previous = None
                for ea in idautils.FuncItems(flush):
                    insn = idautils.DecodeInstruction(int(ea))
                    if not insn:
                        continue
                    mnemonic = (idc.print_insn_mnem(int(ea)) or '').lower()
                    for op in insn.ops:
                        if int(op.type) == int(idaapi.o_void):
                            break
                        if int(op.type) == int(idaapi.o_displ) and int(op.addr) == 12:
                            this_member = True
                    if mnemonic in ('call', 'jmp') and int(insn.ops[0].type) == int(idaapi.o_displ):
                        forward.append(int(insn.ops[0].addr) & 0xFFFFFFFF)
                    elif mnemonic in ('call', 'jmp') and int(insn.ops[0].type) == int(idaapi.o_reg):
                        if previous is not None:
                            prior_mnemonic, prior = previous
                            if (prior_mnemonic == 'mov' and int(prior.ops[0].type) == int(idaapi.o_reg)
                                    and int(prior.ops[0].reg) == int(insn.ops[0].reg)
                                    and int(prior.ops[1].type) == int(idaapi.o_displ)):
                                forward.append(int(prior.ops[1].addr) & 0xFFFFFFFF)
                    previous = (mnemonic, insn)
            if not (shared_prefix and widths and branches and valid_entries and this_member
                    and len(forward) == 1 and forward[0] % 4 == 0):
                result = {
                    'error': 'text vcall roles or concrete flush forwarder disagree',
                    'char_slots': a, 'add_slots': b, 'getter': hex(getter),
                }
            else:
                result = {
                    'pointer_size': 4,
                    'slots': {
                        'ISurface_DrawSetTextFont': a[0],
                        'ISurface_DrawSetTextPos': a[1],
                        'ISurface_DrawSetTextColor': a[2],
                        'ISurface_DrawUnicodeChar': a[3],
                        'ISurface_DrawUnicodeCharAdd': b[3],
                        'ISurface_DrawFlushText': a[4],
                        'ISurface_GetCharABCwide': a[-1],
                    },
                    'getter': hex(getter),
                }
"""


def _function_va(new_binary_dir, stem, platform):
    artifact = _load_yaml_mapping(Path(new_binary_dir) / f"{stem}.{platform}.yaml")
    try:
        return int(artifact["func_va"], 0)
    except (KeyError, TypeError, ValueError):
        return None


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
    _ = old_yaml_map, image_base
    char = _function_va(new_binary_dir, "VGUI2_Draw_Character", platform)
    add = _function_va(new_binary_dir, "VGUI2_Draw_CharacterAdd", platform)
    table = _load_yaml_mapping(Path(new_binary_dir) / f"BaseUISurface_vtable.{platform}.yaml")
    if char is None or add is None or not table:
        return False
    entries = table.get("vtable_entries") or {}
    located = await run_walk(
        session,
        LOCATE,
        {
            "char": char,
            "add": add,
            "vtable": {str(index): str(va) for index, va in entries.items()},
            "sequence_length": SOURCE_SEQUENCE_LENGTH,
        },
    )
    slots = located.get("slots") if located.get("pointer_size") == 4 else None
    if not isinstance(slots, dict) or len(slots) != 7:
        if debug:
            print(f"{skill_name}: {located.get('error') or 'incomplete surface slots'}")
        return False
    for name, index in slots.items():
        output = _output_for_symbol(expected_outputs, name)
        if output is None or not isinstance(index, int) or index < 0:
            return False
        write_func_yaml(
            output,
            {
                "func_name": f"vgui2::ISurface::{name.removeprefix('ISurface_')}",
                "vtable_name": "vgui2::ISurface",
                "vfunc_offset": hex(index * 4),
                "vfunc_index": index,
            },
        )
    return True
