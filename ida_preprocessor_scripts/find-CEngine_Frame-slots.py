#!/usr/bin/env python3
"""Infer game activity/wait and audio Frame slots from CEngine::Frame.

The IsActiveApp result guards a zero-only region containing SleepUntilInput
on the same object. The other global-object dispatch dominates that test and
is ICDAudio::Frame (engine/sys_engine.cpp). Reject ambiguous roles rather than
using call ordinals, known slot indices or merged 20/50 timeout constants.
"""

from ida_analyze_util import _output_for_symbol
from ida_preprocessor_scripts._engine_runtime_slots import select_frame_slots
from ida_preprocessor_scripts._vgui_paint_common import artifact, function_address, walk, write_slot

TARGETS = ("IGame_IsActiveApp", "IGame_SleepUntilInput", "ICDAudio_Frame")
DECODE = r"""
flow = flow_at(values['owner'], values['platform'])
calls = []
for call in flow['calls']:
    targets = virtual_targets(call['target'])
    if targets:
        calls.append(dict(ea=call['ea'], block=call['block'], args=call['args'], virtuals=targets))
result = dict(calls=calls, branches=flow['branches'], blocks=flow['blocks'])
"""


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
    _ = old_yaml_map, image_base
    if platform not in {"windows", "linux"} or any(
        _output_for_symbol(expected_outputs, name) is None for name in TARGETS
    ):
        return False
    owner = function_address(new_binary_dir, "CEngine_Frame", platform)
    game = artifact(new_binary_dir, "CGame_vtable", platform)
    if not owner or not game or game.get("vtable_class") != "CGame":
        return False
    flow = await walk(session, DECODE, {"owner": owner, "platform": platform})
    try:
        slots = select_frame_slots(flow, owner)
        for name in ("IGame_IsActiveApp", "IGame_SleepUntilInput"):
            index = slots[name]["offset"] // 4
            if index not in game["vtable_entries"] and str(index) not in game["vtable_entries"]:
                raise ValueError(f"{name}: slot outside current CGame table")
    except (KeyError, TypeError, ValueError) as exc:
        if debug:
            print(f"{skill_name}: {exc}")
        return False
    for name in TARGETS:
        interface, method = name.split("_", 1)
        if not write_slot(expected_outputs, name, interface, method, slots[name]["offset"]):
            return False
        if debug:
            print(f"{skill_name}: {name} offset={slots[name]['offset']:#x} sites={slots[name]['sites']}")
    return True
