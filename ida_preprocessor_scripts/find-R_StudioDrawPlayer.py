#!/usr/bin/env python3
"""Locate R_StudioDrawPlayer (GoldSrc/HL25/CoF families).

ClientDLL_CheckStudioInterface's interface-mismatch diagnostic is unique;
its body passes &pStudioAPI to the client studio interface, and the global's
static initializer is the r_studio_interface_t studio object
{STUDIO_INTERFACE_VERSION, R_StudioDrawModel, R_StudioDrawPlayer}, so the +8
slot is the interface entry. The entry (or its GCC .part.N cold clone,
reached by a direct call/jmp) must reference "models/player/%s/%s.mdl", and
the remaining format-string owner must match the verified
studioapi_SetupPlayerModel artifact. SvEngine ships a different diagnostic
wording and is covered by find-R_StudioDrawPlayer-svencoop instead.
"""

from ida_preprocessor_scripts._studio_player_model_common import (
    HL_STUDIO_STRING,
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
        studio_string=HL_STUDIO_STRING,
        new_binary_dir=new_binary_dir,
        debug=debug,
    )
