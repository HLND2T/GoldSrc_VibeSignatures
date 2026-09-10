#!/usr/bin/env python3
"""Read SDK cl_enginefuncs slot 61, the CL_CreateVisibleEntity callback."""

from ida_preprocessor_scripts._engine_public_callback_common import preprocess_engine_callback


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
    _ = skill_name, old_yaml_map, debug
    return await preprocess_engine_callback(
        session,
        expected_outputs,
        new_binary_dir,
        platform,
        image_base,
        name="CL_CreateVisibleEntity",
        slot=61,
    )
