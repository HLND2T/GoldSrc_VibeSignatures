#!/usr/bin/env python3
"""Recover the BaseUI pointer and its two startup interface slots.

The BaseUI factory result is cached in the global tested by the startup guard.
Both virtual calls in that function must use the platform's observed IBaseUI
layout and the source arguments 2 and 7. The immediate arguments are never
treated as slot numbers.
"""

from pathlib import Path

from ida_analyze_util import _load_yaml_mapping
from ida_preprocessor_scripts._direct_gv_common import inspect_owner_artifact, write_located_globals
from ida_preprocessor_scripts._engine_private_globals_common import run_walk
from ida_preprocessor_scripts._vgui_paint_common import write_slot

OWNER = "VGuiWrap2_Startup"
GV_NAME = "staticUIFuncs"
INITIALIZE = "IBaseUI_Initialize"
START = "IBaseUI_Start"

WALK = r"""
import ida_funcs, ida_nalt, idautils

owner = int(values['owner'], 0)
offsets = tuple(values['offsets'])
entries = scan(owner)
if entries is None:
    result = {'error': 'startup artifact is not a function start'}
else:
    literal_eas = []
    strings = idautils.Strings(default_setup=False)
    strings.setup(strtypes=[ida_nalt.STRTYPE_C], minlen=4)
    for item in strings:
        if str(item) == 'BaseUI001':
            literal_eas.append(int(item.ea))
    sites = set()
    for literal_ea in literal_eas:
        for ref in idautils.XrefsTo(literal_ea, 0):
            function = ida_funcs.get_func(int(ref.frm))
            if function is not None and int(function.start_ea) == owner:
                sites.add(int(ref.frm))
    calls = [(int(entry['ea']), int(entry['insn'].ops[0].addr)) for entry in entries
             if entry['mnem'] == 'call' and int(entry['insn'].ops[0].type) == int(idaapi.o_displ)
             and int(entry['insn'].ops[0].addr) in offsets]
    if len(sites) != 1 or len(calls) != 2 or [slot for _, slot in calls] != list(offsets):
        result = {'error': 'BaseUI query or startup vcall sequence is ambiguous',
                  'sites': [hex(x) for x in sorted(sites)], 'calls': calls}
    else:
        site = next(iter(sites))
        written_after = {gv for entry in entries if int(entry['ea']) > site
                         for gv in entry['written']}
        guards = []
        for index, entry in enumerate(entries):
            if int(entry['ea']) >= site:
                break
            if entry['written'] or len(entry['targets']) != 1:
                continue
            gv = int(next(iter(entry['targets'])))
            if gv in written_after:
                guards.append((index, gv))
        unique = sorted({gv for _, gv in guards})
        if len(unique) != 1:
            result = {'error': 'startup cached pointer guard is ambiguous',
                      'guards': [hex(x) for x in unique]}
        else:
            gv = unique[0]
            indexes = [i for i, entry in enumerate(entries) if gv in entry['targets']]
            carrier = first_addressable(entries, indexes)
            located = access(carrier, gv)
            result = ({'pointer_size': 4, 'gv': located, 'calls': [hex(ea) for ea, _ in calls]}
                      if located else {'error': 'no addressable staticUIFuncs access'})
"""


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
    _ = skill_name, old_yaml_map
    if platform not in {"windows", "linux"}:
        return False
    artifact = _load_yaml_mapping(Path(new_binary_dir) / f"{OWNER}.{platform}.yaml")
    if not artifact or not isinstance(artifact.get("func_name"), str):
        return False
    owner = await inspect_owner_artifact(
        session, new_binary_dir, platform, image_base, OWNER, func_name=artifact["func_name"]
    )
    if owner is None:
        return False
    offsets = (4, 8) if platform == "windows" else (8, 12)
    located = await run_walk(session, WALK, {"owner": hex(owner["owner_ea"]), "offsets": offsets})
    if debug:
        print(f"{skill_name}: {located}")
    if located.get("pointer_size") != 4 or not isinstance(located.get("gv"), dict):
        return False
    if not await write_located_globals(
        session, expected_outputs, platform, image_base, owner, {GV_NAME: located["gv"]}
    ):
        return False
    return all(
        (
            write_slot(expected_outputs, INITIALIZE, "IBaseUI", "Initialize", offsets[0]),
            write_slot(expected_outputs, START, "IBaseUI", "Start", offsets[1]),
        )
    )
