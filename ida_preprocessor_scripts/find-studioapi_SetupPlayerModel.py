#!/usr/bin/env python3
"""Locate studioapi_SetupPlayerModel (GoldSrc/HL25/CoF families).

ClientDLL_CheckStudioInterface's interface-mismatch diagnostic is unique;
its body passes &engine_studio_api to the client studio interface, and
engine_studio_api_t stores studioapi_SetupPlayerModel at fixed slot 0x7C.
The slot function must reference "models/player/%s/%s.mdl". SvEngine ships
a different diagnostic wording and its SvEngine builds are covered by
find-studioapi_SetupPlayerModel-svencoop instead.
"""

from ida_preprocessor_scripts._studio_player_model_common import (
    HL_STUDIO_STRING,
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
        studio_string=HL_STUDIO_STRING,
        debug=debug,
    )
