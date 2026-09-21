#!/usr/bin/env python3
"""Locate studioapi_SetupModel, pbodypart and psubmodel on SvEngine.

Same engine_studio_api slot-0x50 chain as the generic finder, but SvEngine
words the ClientDLL_CheckStudioInterface diagnostic differently. Linux is
PIC: the table VA comes from lea reg, [ebx + disp32], and the out-param
stores of &pbodypart / &psubmodel are lea+mov through the same GOT anchor.
"""

from ida_preprocessor_scripts._studio_player_model_common import SVC_STUDIO_STRING
from ida_preprocessor_scripts._studio_setup_common import preprocess_studio_setup_model


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
    return await preprocess_studio_setup_model(
        session,
        expected_outputs,
        platform,
        image_base,
        studio_string=SVC_STUDIO_STRING,
        debug=debug,
    )
