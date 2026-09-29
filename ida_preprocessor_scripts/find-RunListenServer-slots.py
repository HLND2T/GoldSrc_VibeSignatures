#!/usr/bin/env python3
"""Recover eight interface slots from RunListenServer's actual call dataflow.

Source: engine/sys_dll2.cpp. The Init calls take the launcher's instance and
guard initialization; Load takes false/basedir/cmdline. SetQuitting(0)
dominates video initialization. GetQuitting controls the message-loop exit,
Frame is its other engine dispatch, and the Load failure path identifies the
two Shutdown slots. Duplicate cleanup callsites must agree on one slot.

Reuse the CFG/reaching-value decoder, including Linux GOT provenance. No fixed
call ordinal, byte window, cross-version index, old artifact signature or LLM
interpretation selects a slot. Current concrete vtables bound every result.
IEngine_Init in the issue is actually IGame::Init, as confirmed by ELF symbols.
"""

from ida_analyze_util import _output_for_symbol
from ida_preprocessor_scripts._engine_runtime_slots import select_runlistenserver_slots
from ida_preprocessor_scripts._vgui_paint_common import artifact, function_address, walk, write_slot


TARGETS = (
    "IGame_Init",
    "IEngine_Load",
    "IVideoMode_Init",
    "IEngine_Frame",
    "IEngine_SetQuitting",
    "IEngine_GetQuitting",
    "IGame_Shutdown",
    "IVideoMode_Shutdown",
)
TABLES = {"IEngine": "CEngine", "IGame": "CGame", "IVideoMode": "CVideoMode_OpenGL"}
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
    owner = function_address(new_binary_dir, "RunListenServer", platform)
    eng = artifact(new_binary_dir, "eng", platform)
    video = artifact(new_binary_dir, "videomode", platform)
    tables = {
        interface: artifact(new_binary_dir, concrete + "_vtable", platform) for interface, concrete in TABLES.items()
    }
    if not owner or not eng or not video or not all(tables.values()):
        return False
    flow = await walk(session, DECODE, {"owner": owner, "platform": platform})
    try:
        slots = select_runlistenserver_slots(flow, owner, int(eng["gv_va"], 0), int(video["gv_va"], 0), platform)
        for name in TARGETS:
            interface, _ = name.split("_", 1)
            table = tables[interface]
            if table.get("vtable_class") != TABLES[interface]:
                raise ValueError("concrete vtable identity mismatch")
            index = slots[name]["offset"] // 4
            entries = table["vtable_entries"]
            if index not in entries and str(index) not in entries:
                raise ValueError(f"{name}: slot outside the current concrete vtable")
    except (KeyError, TypeError, ValueError) as exc:
        if debug:
            print(f"{skill_name}: {exc}")
        return False
    for name in TARGETS:
        interface, method = name.split("_", 1)
        if not write_slot(expected_outputs, name, interface, method, slots[name]["offset"]):
            return False
        if debug:
            print(
                f"{skill_name}: {name} offset={slots[name]['offset']:#x} sites={[hex(ea) for ea in slots[name]['sites']]}"
            )
    return True
