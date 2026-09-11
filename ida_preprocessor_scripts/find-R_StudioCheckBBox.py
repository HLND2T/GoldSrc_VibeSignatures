#!/usr/bin/env python3
"""Materialize the public StudioCheckBBox callback solely as a CullBox anchor.

The interface-mismatch diagnostic owns the engine studio API passed to the
client; common/r_studioint.h defines StudioCheckBBox at x86 slot 21.
"""

from ida_analyze_util import _inspect_function_via_mcp, _output_for_symbol, write_func_yaml
from ida_preprocessor_scripts._studio_player_model_common import (
    HL_STUDIO_STRING,
    SVC_STUDIO_STRING,
    locate_studio_slot,
)


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
    _ = skill_name, old_yaml_map, new_binary_dir, debug
    targets = set()
    for diagnostic in (HL_STUDIO_STRING, SVC_STUDIO_STRING):
        located = await locate_studio_slot(session, diagnostic, 21 * 4)
        if located and not located.get("error") and located.get("pointer_size") == 4:
            targets.add(int(located["slot_va"], 0))
    if len(targets) != 1:
        return False
    target = targets.pop()
    name = "R_StudioCheckBBox"
    output = _output_for_symbol(expected_outputs, name)
    function = await _inspect_function_via_mcp(session, target, image_base, name)
    if not function or not output:
        return False
    write_func_yaml(
        output, {key: function[key] for key in ("func_name", "func_va", "func_rva", "func_size", "func_sig")}
    )
    return True
