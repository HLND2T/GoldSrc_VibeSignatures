#!/usr/bin/env python3
"""Locate R_StudioDrawPlayer (SvEngine family).

Same anchor chain as find-R_StudioDrawPlayer, anchored on the SvEngine
wording of the ClientDLL_CheckStudioInterface interface-mismatch
diagnostic.
"""

from ida_preprocessor_scripts._studio_player_model_common import (
    SVC_STUDIO_STRING,
    preprocess_studio_draw_player,
)

TARGET_NAME = "R_StudioDrawPlayer"


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
    return await preprocess_studio_draw_player(
        session,
        expected_outputs,
        platform,
        image_base,
        target_name=TARGET_NAME,
        studio_string=SVC_STUDIO_STRING,
        new_binary_dir=new_binary_dir,
        debug=debug,
    )
