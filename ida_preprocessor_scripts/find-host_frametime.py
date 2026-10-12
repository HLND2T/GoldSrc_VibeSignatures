#!/usr/bin/env python3
"""Recover the frame filter's clamped double, including HL25's inline body.

The approved owning-function chain is shared with find-Host_FilterTime.
This direct-locator exception is independently validated on every x86 engine:
the literal double upper-limit store names one writable object, its 8-byte
access is checked, and its reference is inside the anchored filter (or the
verified _Host_Frame when inlined). LLM reference matching adds no information
to this exact store dataflow. No reference/old address or signature discovers
the object. The output signature begins at the verified access instruction.
"""

from ida_analyze_util import _load_yaml_mapping
from ida_preprocessor_scripts._direct_gv_common import write_located_globals
from ida_preprocessor_scripts._engine_private_globals_common import owner_context
from ida_preprocessor_scripts._server_physics_common import finish_globals, locate_host


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
    frame = _load_yaml_mapping(f"{new_binary_dir}/_Host_Frame.{platform}.yaml")
    if not frame or frame.get("func_name") not in ("_Host_Frame", "_Z11_Host_Framef"):
        return False
    located = await locate_host(session, int(frame["func_va"], 0))
    if debug:
        print(f"{skill_name}: {located}")
    if located.get("error") or not all(0 < value < 1 for value in located["clamps"]):
        return False
    owner = await owner_context(session, int(located["owner"], 0), image_base, "frame_filter_owner")
    if owner is None:
        return False
    found = await write_located_globals(
        session, expected_outputs, platform, image_base, owner, {"host_frametime": located["gv"]}
    )
    return found and await finish_globals(session, expected_outputs, platform)
