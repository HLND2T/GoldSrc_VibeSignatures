#!/usr/bin/env python3
"""Locate studioapi_SetupPlayerModel on SvEngine (svencoop-*).

Same engine_studio_api slot-0x7C chain as the generic finder, but SvEngine
words the ClientDLL_CheckStudioInterface diagnostic differently, and its
Linux build is PIC: the table VA comes from lea reg, [ebx + disp32] with
the ebx GOT anchor recovered from the call-thunk/add-ebx prologue. Linux
may also have two string owners; the locator collapses on the unique table
VA instead of the owner.
"""

from ida_preprocessor_scripts._studio_player_model_common import (
    SVC_STUDIO_STRING,
    preprocess_studio_setup_player_model,
)

TARGET_NAME = "studioapi_SetupPlayerModel"


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
    return await preprocess_studio_setup_player_model(
        session,
        expected_outputs,
        platform,
        image_base,
        target_name=TARGET_NAME,
        studio_string=SVC_STUDIO_STRING,
        debug=debug,
    )
