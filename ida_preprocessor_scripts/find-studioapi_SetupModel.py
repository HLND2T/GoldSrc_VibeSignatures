#!/usr/bin/env python3
"""Locate studioapi_SetupModel, pbodypart and psubmodel (GoldSrc/HL25/CoF).

ClientDLL_CheckStudioInterface's interface-mismatch diagnostic is unique;
its body passes &engine_studio_api to the client studio interface, and
common/r_studioint.h stores studioapi_SetupModel at x86 slot 20. The
wrapper assigns ``*ppbodypart = &pbodypart`` and ``*ppsubmodel = &psubmodel``
(engine/r_studio.c); those two address-of immediates (or PIC lea+store
pairs) are the globals. SvEngine ships a different diagnostic wording and
is covered by find-studioapi_SetupModel-svencoop instead.
"""

from ida_preprocessor_scripts._studio_player_model_common import HL_STUDIO_STRING
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
        studio_string=HL_STUDIO_STRING,
        debug=debug,
    )
