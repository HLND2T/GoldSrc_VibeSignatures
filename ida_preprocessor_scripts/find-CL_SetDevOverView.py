#!/usr/bin/env python3
"""Locate CL_SetDevOverView and the gDevOverview state it mutates.

``engine/cl_spectator.c`` prints the overview parameters when
``dev_overview.value < 2``; that banner is the only literal the function owns
and it resolves to exactly one function on every configured engine build.

``gDevOverview`` is an ``overviewInfo_t`` — ``vec3_t origin; float z_min,
z_max, zoom; qboolean rotated`` — i.e. seven consecutive four-byte members, and
``CL_SetDevOverView`` is the function that reads or writes all seven. That whole
shape is the anchor: exactly one writable-data address in the body has each of
``+0 +4 +8 +0xc +0x10 +0x14 +0x18`` separately referenced, so no byte pattern and
no LLM step is needed. MetaHookSv instead disassembles 0x300 bytes, arms on a
``PUSH 0x30``, collects up to six float loads and keeps the lowest address; that
heuristic is not reproducible across the GCC x87 and MSVC SSE bodies here.
"""

from ida_preprocessor_scripts._direct_gv_common import write_located_globals
from ida_preprocessor_scripts._engine_private_globals_common import (
    inspect_func,
    owner_context,
    run_walk,
)
from ida_analyze_util import _output_for_symbol, write_func_yaml

FUNC_NAME = "CL_SetDevOverView"
GV_NAME = "gDevOverview"

LITERAL = " Overview: Zoom %.2f, Map Origin (%.2f, %.2f, %.2f), Z Min %.2f, Z Max %.2f, Rotated %i\n"
# overviewInfo_t: origin[3], z_min, z_max, zoom, rotated.
OVERVIEW_MEMBER_OFFSETS = (0, 4, 8, 0xC, 0x10, 0x14, 0x18)

WALK = r"""
owner = exact_string_owner(values['literal'])
if owner is None:
    result = {'error': 'overview banner has no single owning function'}
else:
    entries = scan(owner)
    if entries is None:
        result = {'error': 'overview banner owner is not a function start'}
    else:
        mapping = single_globals(entries)
        offsets = tuple(values['offsets'])
        bases = [gv for gv in sorted(mapping) if all(gv + off in mapping for off in offsets)]
        if len(bases) != 1:
            result = {'error': 'overviewInfo_t candidate is not unique: %s' % [hex(b) for b in bases]}
        else:
            located = access(first_addressable(entries, mapping[bases[0]]), bases[0])
            if located is None:
                result = {'error': 'no addressable gDevOverview reference'}
            else:
                result = {'pointer_size': 4, 'owner_ea': hex(owner), 'gv': located}
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
    func_output = _output_for_symbol(expected_outputs, FUNC_NAME)
    if func_output is None or _output_for_symbol(expected_outputs, GV_NAME) is None:
        return False

    located = await run_walk(session, WALK, {"literal": LITERAL, "offsets": list(OVERVIEW_MEMBER_OFFSETS)})
    if located.get("error") or located.get("pointer_size") != 4:
        if debug:
            print(f"{skill_name}: {located.get('error')}")
        return False
    owner_ea = int(located["owner_ea"], 0)

    function = await inspect_func(session, owner_ea, image_base, FUNC_NAME)
    owner = await owner_context(session, owner_ea, image_base, FUNC_NAME)
    if not function or owner is None:
        if debug:
            print(f"{skill_name}: could not inspect {FUNC_NAME} at {owner_ea:#x}")
        return False
    if not await write_located_globals(
        session, expected_outputs, platform, image_base, owner, {GV_NAME: located["gv"]}
    ):
        return False
    write_func_yaml(func_output, function)
    if debug:
        print(f"{skill_name}: {FUNC_NAME}={owner_ea:#x} {GV_NAME}={located['gv']['gv_ea']}")
    return True
