#!/usr/bin/env python3
"""Recover vup/vright/vpn by proving vec3 copies to arguments 2/3/4.

Direct-locator exception: GetViewInfo's verified ABI slot and all twelve
component copies uniquely identify the globals on all 15 engine binaries.
Track actual operands through MOV, SSE, x87 and PIC address loads; never use
global-address sorting, instruction ordinals or old output signatures.
The first argument must agree with the already-covered r_origin artifact.
Sven 8948 GOT pointers and 10257 GOTOFF LEAs resolve to the vector objects.
"""

from pathlib import Path

from ida_analyze_util import _load_yaml_mapping
from ida_preprocessor_scripts._direct_gv_common import inspect_owner_artifact, write_located_globals
from ida_preprocessor_scripts._studio_view_info import locate_vectors

FUNC_NAME = "studioapi_GetViewInfo"
GLOBAL_NAMES = ("vup", "vright", "vpn")


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
    _ = old_yaml_map
    if platform not in {"windows", "linux"}:
        return False
    owner = await inspect_owner_artifact(session, new_binary_dir, platform, image_base, FUNC_NAME)
    origin = _load_yaml_mapping(Path(new_binary_dir) / f"r_origin.{platform}.yaml")
    if owner is None or not origin or origin.get("gv_name") != "r_origin":
        return False
    located = await locate_vectors(session, owner["owner_ea"])
    if located.get("error") or located.get("pointer_size") != 4:
        if debug:
            print(f"{skill_name}: {located}")
        return False
    vectors = located["vectors"]
    if int(vectors[0]["gv_ea"], 0) != int(origin["gv_va"], 0):
        return False
    return await write_located_globals(
        session, expected_outputs, platform, image_base, owner, dict(zip(GLOBAL_NAMES, vectors[1:]))
    )
