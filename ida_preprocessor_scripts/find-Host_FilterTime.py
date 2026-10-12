#!/usr/bin/env python3
"""Find the independent frame filter, never label its inlined caller as it.

Use its own -sys_ticrate literal where present. WON builds lack that option:
inspect the direct callees of the verified _Host_Frame, selecting the single
callee that clamps an 8-byte global to fractional frame limits. No call ordinal
or previous output signature participates. HL25 Windows inlines this function
into _Host_Frame and does not register this producer.
"""

from ida_analyze_util import _load_yaml_mapping, _output_for_symbol, write_func_yaml
from ida_preprocessor_scripts._engine_private_globals_common import inspect_func
from ida_preprocessor_scripts._server_physics_common import locate_host, preserve_functions


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
    artifact = _load_yaml_mapping(f"{new_binary_dir}/_Host_Frame.{platform}.yaml")
    if not artifact or artifact.get("func_name") not in ("_Host_Frame", "_Z11_Host_Framef"):
        return False
    frame = int(artifact["func_va"], 0)
    located = await locate_host(session, frame)
    if debug:
        print(f"{skill_name}: {located}")
    if located.get("error") or int(located["owner"], 0) == frame:
        return False
    payload = await inspect_func(session, int(located["owner"], 0), image_base, "Host_FilterTime")
    output = _output_for_symbol(expected_outputs, "Host_FilterTime")
    if payload is None or output is None:
        return False
    write_func_yaml(output, payload)
    return await preserve_functions(session, expected_outputs, platform, image_base, ["Host_FilterTime"])
