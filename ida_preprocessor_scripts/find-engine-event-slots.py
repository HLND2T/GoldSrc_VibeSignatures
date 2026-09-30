#!/usr/bin/env python3
"""Recover six engine event-interface slots from current method/dataflow roles.

Key_Event identifies the CEngine key method (including resolved ELF PLT calls).
Its reciprocal key/button stores identify the mouse method; the trapping-byte
getter and Frame's DLL-state getter identify IsTrapping/GetState. Native
WindowProc or SDL SleepUntilInput supplies video/window-position dispatches.
See engine/sys_engine.cpp and sys_mainwind.cpp / sys_sdlwind.cpp.

All six outputs are slot-only. No field displacement, slot index, call ordinal
or old signature is used as an anchor. HandleSDLEvent is inline in all nine
configured SDL targets; use the verified SleepUntilInput body, not a fake
standalone function alias. Export only needed flow fields to keep MCP payloads
bounded without changing the shared transport.
"""

from ida_analyze_util import _FUNCTION_OWNER_RECOVERY_PY_EVAL, _output_for_symbol
from ida_preprocessor_scripts._engine_runtime_slots import select_event_slots
from ida_preprocessor_scripts._vgui_paint_common import artifact, walk, write_slot

TARGETS = (
    "IEngine_TrapKey_Event",
    "IEngine_TrapMouse_Event",
    "IEngine_IsTrapping",
    "IEngine_GetState",
    "IVideoMode_IsWindowedMode",
    "IGame_SetWindowXY",
)
TABLES = {"IEngine": "CEngine", "IGame": "CGame", "IVideoMode": "CVideoMode_OpenGL"}
DECODE = (
    "import ida_auto, ida_bytes, ida_funcs, ida_segment, ida_ua, idaapi, idautils, idc, json\n"
    + _FUNCTION_OWNER_RECOVERY_PY_EVAL
    + r"""
def project(entry, virtual_only=False):
    if ida_funcs.get_func(entry) is None:
        _ensure_function_owner(entry, expected_entry=entry)
    flow = flow_at(entry, values['platform'])
    calls = []
    for call in flow['calls']:
        targets = virtual_targets(call['target'])
        if virtual_only and not targets:
            continue
        calls.append(dict(ea=call['ea'], block=call['block'], args=call['args'][:3],
                          direct=call.get('direct'), virtuals=targets))
    projected = dict(entry=entry, calls=calls, branches=flow['branches'], blocks=flow['blocks'])
    if not virtual_only:
        projected.update(returns=flow['returns'], stores=flow['stores'])
    return projected
engine = {index: dict(address=entry, flow=project(entry)) for index,entry in values['entries'].items()}
result = dict(engine=engine, event=project(values['event'], virtual_only=True))
"""
)


def slot_offset(data):
    index = data["vfunc_index"]
    offset = int(data["vfunc_offset"], 0)
    if isinstance(index, bool) or not isinstance(index, int) or index < 0 or offset != index * 4:
        raise ValueError("invalid current interface slot")
    return offset


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
    _ = old_yaml_map, image_base
    if platform not in {"windows", "linux"} or any(
        _output_for_symbol(expected_outputs, name) is None for name in TARGETS
    ):
        return False
    tables = {
        interface: artifact(new_binary_dir, concrete + "_vtable", platform) for interface, concrete in TABLES.items()
    }
    frame = artifact(new_binary_dir, "CEngine_Frame", platform)
    frame_slot = artifact(new_binary_dir, "IEngine_Frame", platform)
    key = artifact(new_binary_dir, "Key_Event", platform)
    eng = artifact(new_binary_dir, "eng", platform)
    video = artifact(new_binary_dir, "videomode", platform)
    update = artifact(new_binary_dir, "IVideoMode_UpdateWindowPosition", platform)
    event = artifact(new_binary_dir, "CGame_WindowProc", platform) if platform == "windows" else None
    sdl = event is None
    if sdl:
        event = artifact(new_binary_dir, "CGame_SleepUntilInput", platform)
    if not all(tables.values()) or not all((frame, frame_slot, key, eng, video, update, event)):
        return False
    try:
        for interface, table in tables.items():
            if table.get("vtable_class") != TABLES[interface]:
                raise ValueError("current vtable class mismatch")
        entries = {int(index): int(address, 0) for index, address in tables["IEngine"]["vtable_entries"].items()}
        frame_index = slot_offset(frame_slot) // 4
        if entries.get(frame_index) != int(frame["func_va"], 0):
            raise ValueError("Frame slot/table disagrees with concrete artifact")
        flow = await walk(
            session, DECODE, {"entries": entries, "event": int(event["func_va"], 0), "platform": platform}
        )
        if flow.get("error"):
            raise ValueError(flow["error"])
        slots = select_event_slots(
            flow["engine"],
            flow["event"],
            frame_index,
            int(key["func_va"], 0),
            int(eng["gv_va"], 0),
            int(video["gv_va"], 0),
            slot_offset(update),
            sdl=sdl,
        )
        for name in TARGETS:
            table = tables[name.split("_", 1)[0]]["vtable_entries"]
            index = slots[name]["offset"] // 4
            if index not in table and str(index) not in table:
                raise ValueError(f"{name}: slot outside current table")
    except (KeyError, TypeError, ValueError) as exc:
        if debug:
            print(f"{skill_name}: {exc}")
        return False
    for name in TARGETS:
        interface, method = name.split("_", 1)
        if not write_slot(expected_outputs, name, interface, method, slots[name]["offset"]):
            return False
        if debug:
            print(f"{skill_name}: {name} {slots[name]}")
    return True
