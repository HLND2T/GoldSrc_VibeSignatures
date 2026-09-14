#!/usr/bin/env python3
"""Locate studioapi_StudioSetRenderamt (GoldSrc/HL25/CoF/SvEngine).

ClientDLL_CheckStudioInterface's interface-mismatch diagnostic is unique; its
body passes &engine_studio_api to the client studio interface, and the table's
fixed ABI slot 0xAC (common/r_studioint.h, the CZero-era addition) is
studioapi_StudioSetRenderamt. The accessor stores iRenderamt into
currententity->curstate.renderamt and feeds CL_FxBlend(currententity)/255.0
into r_blend; only its function entry is emitted here and
find-CL_FxBlend consumes this artifact for the sole-call walk. Validated on
hl-4554/6153/8684/10210 (table code-pointer run 46), cof-5936 and
svencoop-10257 (run 47), both platforms where shipped; SvEngine Linux encodes
the table through its PIC GOTOFF prologue exactly like the other slots.
"""

from ida_preprocessor_scripts._studio_player_model_common import (
    HL_STUDIO_STRING,
    SLOT_SHAPE_SKIP_GVS,
    SVC_STUDIO_STRING,
    preprocess_studio_slot,
)

TARGET_FUNC_NAME = "studioapi_StudioSetRenderamt"
SLOT_OFFSET = 0xAC


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
    for studio_string in (HL_STUDIO_STRING, SVC_STUDIO_STRING):
        if await preprocess_studio_slot(
            session,
            expected_outputs,
            platform,
            image_base,
            func_name=TARGET_FUNC_NAME,
            slot_offset=SLOT_OFFSET,
            shape=SLOT_SHAPE_SKIP_GVS,
            gv_names=(),
            studio_string=studio_string,
            debug=debug,
        ):
            return True
    return False
