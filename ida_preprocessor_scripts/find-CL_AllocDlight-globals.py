#!/usr/bin/env python3
"""Recover cl_dlights from the verified CL_AllocDlight body."""

from ida_preprocessor_scripts._renderer_private_globals_common import preprocess_light_array


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
    _ = skill_name, old_yaml_map
    return await preprocess_light_array(
        session,
        expected_outputs,
        new_binary_dir,
        platform,
        image_base,
        owner_name="CL_AllocDlight",
        gv_name="cl_dlights",
        debug=debug,
    )
