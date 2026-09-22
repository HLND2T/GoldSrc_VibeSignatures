#!/usr/bin/env python3
"""Locate GetViewInfo through the shared studio interface table's ABI slot 0x30.

common/r_studioint.h defines slot 12; engine/r_studio.c copies r_origin, vup,
vright and vpn to four arguments. Validate that dataflow on the current binary.
The existing diagnostic/table locator covers GoldSrc, HL25, CoF and SvEngine.
Linux spells the function studioapi_GetViewInfo (HL) or
_Z21studioapi_GetViewInfoPfS_S_S_ (Sven); use its demangled artifact identity.
No prior artifact signature participates in discovery.
"""

from ida_analyze_util import _output_for_symbol, write_func_yaml
from ida_preprocessor_scripts._engine_private_globals_common import inspect_func
from ida_preprocessor_scripts._studio_player_model_common import HL_STUDIO_STRING, SVC_STUDIO_STRING, locate_studio_slot
from ida_preprocessor_scripts._studio_view_info import locate_vectors

FUNC_NAME = "studioapi_GetViewInfo"
SLOT_OFFSET = 12 * 4


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
    _ = old_yaml_map, new_binary_dir
    output = _output_for_symbol(expected_outputs, FUNC_NAME)
    if output is None or platform not in {"windows", "linux"}:
        return False
    candidates = []
    for literal in (HL_STUDIO_STRING, SVC_STUDIO_STRING):
        located = await locate_studio_slot(session, literal, SLOT_OFFSET)
        if located and located.get("error") == "studio interface string count 0":
            continue
        if not located or located.get("error"):
            return False
        candidates.append(located)
    if len(candidates) != 1:
        return False
    address = int(candidates[0]["slot_va"], 0)
    vectors = await locate_vectors(session, address)
    if vectors.get("error") or vectors.get("pointer_size") != 4:
        if debug:
            print(f"{skill_name}: {vectors}")
        return False
    function = await inspect_func(session, address, image_base, FUNC_NAME)
    if not function:
        return False
    write_func_yaml(output, function)
    if debug:
        print(f"{skill_name}: table={candidates[0]['table_ea']} slot=0x30 function={address:#x}")
    return True
