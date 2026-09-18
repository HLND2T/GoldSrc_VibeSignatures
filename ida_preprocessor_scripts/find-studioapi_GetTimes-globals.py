#!/usr/bin/env python3
"""Recover logical cl_time and cl_oldtime aliases from studioapi_GetTimes."""

from ida_preprocessor_scripts._studio_player_model_common import (
    HL_STUDIO_STRING,
    preprocess_studio_get_times_globals,
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
    _ = skill_name, old_yaml_map
    return await preprocess_studio_get_times_globals(
        session,
        expected_outputs,
        new_binary_dir,
        platform,
        image_base,
        studio_string=HL_STUDIO_STRING,
        debug=debug,
    )
