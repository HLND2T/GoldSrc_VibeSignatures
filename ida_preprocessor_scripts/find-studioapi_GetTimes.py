#!/usr/bin/env python3
"""Locate studioapi_GetTimes from engine_studio_api slot 0x28."""

from ida_preprocessor_scripts._studio_player_model_common import (
    HL_STUDIO_STRING,
    SLOT_SHAPE_SKIP_GVS,
    preprocess_studio_slot,
)

TARGET_FUNC_NAME = "studioapi_GetTimes"


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
    _ = skill_name, old_yaml_map, new_binary_dir
    return await preprocess_studio_slot(
        session,
        expected_outputs,
        platform,
        image_base,
        func_name=TARGET_FUNC_NAME,
        slot_offset=0x28,
        shape=SLOT_SHAPE_SKIP_GVS,
        gv_names=(),
        studio_string=HL_STUDIO_STRING,
        debug=debug,
    )
