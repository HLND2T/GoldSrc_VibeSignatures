#!/usr/bin/env python3
"""Locate R_StudioDrawModel on SvEngine (svencoop-*).

Same pStudioAPI -> studio {1, R_StudioDrawModel(+4), R_StudioDrawPlayer(+8)}
chain as the generic finder, but SvEngine words the
ClientDLL_CheckStudioInterface diagnostic differently and its Linux build is
PIC. The +8 slot must equal the verified R_StudioDrawPlayer artifact (DAG
input), which anchors the interface identity so the +4 slot is
R_StudioDrawModel (validated 2026-09-10: hw.dll studio+4 0x1D90580 / +8
0x1D8A390, hw.so 0xAD840/0xAD7F0). Linux may also have two string owners;
the locator collapses on the unique pStudioAPI candidate instead of the
owner.
"""

from ida_preprocessor_scripts._studio_player_model_common import (
    SVC_STUDIO_STRING,
    preprocess_studio_draw_model,
)

TARGET_NAME = "R_StudioDrawModel"


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
    return await preprocess_studio_draw_model(
        session,
        expected_outputs,
        platform,
        image_base,
        target_name=TARGET_NAME,
        studio_string=SVC_STUDIO_STRING,
        new_binary_dir=new_binary_dir,
        debug=debug,
    )
