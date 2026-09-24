#!/usr/bin/env python3
"""Locate the two text callbacks from cl_enginefuncs' SDK-defined table.

Slots 117 and 118 are the source-level entries in engine/cdll_int.c. A SvEngine
entry may be a forwarding wrapper, so the shared callback resolver follows
only a side-effect-free, single-target thunk. The resulting body must contain
an iswprint guard and several virtual surface calls, not just be executable.
"""

from pathlib import Path

from ida_preprocessor_scripts._engine_private_globals_common import run_walk
from ida_preprocessor_scripts._engine_public_callback_common import preprocess_engine_callback


VERIFY_TEXT_BODY = r"""
TARGET = int(values['target'])
owner = ida_funcs.get_func(TARGET)
if owner is None or int(owner.start_ea) != TARGET:
    result = {'error': 'callback target is not a function entry'}
else:
    printable_calls = []
    virtual_calls = []
    for ea in idautils.FuncItems(TARGET):
        insn = idautils.DecodeInstruction(int(ea))
        if not insn or (idc.print_insn_mnem(int(ea)) or '').lower() != 'call':
            continue
        op = insn.ops[0]
        if 'iswprint' in (idc.print_operand(int(ea), 0) or '').lower():
            printable_calls.append(int(ea))
        elif int(op.type) == int(idaapi.o_displ):
            displacement = int(op.addr) & 0xFFFFFFFF
            if displacement % 4 == 0:
                virtual_calls.append((int(ea), displacement))
    if len(printable_calls) != 1 or len(virtual_calls) < 5:
        result = {'error': 'text callback lacks the printable-character and surface-call path'}
    elif not any(ea > printable_calls[0] for ea, _ in virtual_calls):
        result = {'error': 'no virtual draw call follows iswprint'}
    else:
        result = {'pointer_size': 4, 'virtual_calls': len(virtual_calls)}
"""


async def _validate(session, target):
    found = await run_walk(session, VERIFY_TEXT_BODY, {"target": target})
    return found.get("pointer_size") == 4 and not found.get("error")


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
    _ = skill_name, old_yaml_map, debug
    gamever = Path(new_binary_dir).parent.name
    targets = (
        ("VGUI2_Draw_Character", 117, "VGUI2_Draw_Character(int, int, int, unsigned int)"),
        (
            "VGUI2_Draw_CharacterAdd",
            118,
            "VGUI2_Draw_CharacterAdd(int, int, int, int, int, int, unsigned int)",
        ),
    )
    for name, slot, sven_name in targets:
        if not await preprocess_engine_callback(
            session,
            expected_outputs,
            new_binary_dir,
            platform,
            image_base,
            name=name,
            slot=slot,
            candidate_validator=_validate,
            artifact_func_name=sven_name if gamever.startswith("svencoop-") else name,
            allow_relative_call_discriminator=(
                gamever.startswith("svencoop-") and platform == "linux" and name == "VGUI2_Draw_CharacterAdd"
            ),
        ):
            return False
    return True
