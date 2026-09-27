#!/usr/bin/env python3
"""Find the actual history-search function called by CL_InterpolateModel.

The second CL_InterpolateModel entry in issue #266 describes
CL_FindInterpolationUpdates (engine/cl_extrap.c). Its own body repeatedly masks
the 64-entry pose-history indices with HISTORY_MASK (0x3f), handles the zero
animtime sentinel, and writes two history pointers. The predecessor is the
interpolator core on hl-8684 Linux and the ordinary interpolator elsewhere.
The mask is checked in the callee's instructions rather than used as a raw
byte signature; exactly one direct callee must have the history-search role.
"""

from pathlib import Path

import ida_analyze_util as u
from ida_preprocessor_scripts._direct_gv_common import inspect_owner_artifact
from ida_preprocessor_scripts._engine_entity_interpolation_common import function_identity
from ida_preprocessor_scripts._engine_private_globals_common import inspect_func, run_walk

TARGET = "CL_FindInterpolationUpdates"
PREDECESSOR = "CL_InterpolateModel"
SPLIT_PREDECESSOR = "CL_InterpolateModel.part.1"

WALK = r"""
import idaapi, ida_funcs, idc

owner = int(values['owner'], 0)
candidates = []
for callee, sites in direct_calls(owner).items():
    function = ida_funcs.get_func(callee)
    entries = scan(callee)
    if function is None or entries is None:
        continue
    masks = [entry for entry in entries if any(
        int(op.type) == int(idaapi.o_imm) and int(op.value) == 63
        for op in entry['insn'].ops)]
    if len(masks) >= 4:
        candidates.append({'ea': hex(callee), 'size': function.end_ea - function.start_ea,
                           'mask_count': len(masks), 'callsites': [hex(site) for site in sites],
                           'name': idc.get_name(callee)})
result = {'candidate': candidates[0]} if len(candidates) == 1 else {
    'error': 'history-search callee is absent or ambiguous', 'candidates': candidates}
"""


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
    _ = skill_name, old_yaml_map
    output = u._output_for_symbol(expected_outputs, TARGET)
    if output is None:
        return False
    is_hl8684_linux = platform == "linux" and Path(new_binary_dir).parent.name == "hl-8684"
    predecessor = SPLIT_PREDECESSOR if is_hl8684_linux else PREDECESSOR
    owner = await inspect_owner_artifact(
        session,
        new_binary_dir,
        platform,
        image_base,
        predecessor,
        func_name=function_identity(new_binary_dir, platform, predecessor),
    )
    if owner is None:
        return False
    found = await run_walk(session, WALK, {"owner": hex(owner["owner_ea"])})
    if not isinstance(found, dict) or found.get("error"):
        if debug:
            print(f"  {TARGET}: locator failed {found}")
        return False
    try:
        ea = int(found["candidate"]["ea"], 0)
    except (KeyError, TypeError, ValueError):
        return False
    identity = function_identity(new_binary_dir, platform, TARGET)
    function = await inspect_func(session, ea, image_base, identity)
    if function is None:
        return False
    u.write_func_yaml(output, function)
    return True
