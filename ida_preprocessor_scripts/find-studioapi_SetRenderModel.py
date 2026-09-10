#!/usr/bin/env python3
"""Locate studioapi_SetRenderModel and r_model (GoldSrc/HL25/CoF).

ClientDLL_CheckStudioInterface's interface-mismatch diagnostic is unique;
its body passes &engine_studio_api to the client studio interface, and the
table's fixed ABI slot 0x90 (common/r_studioint.h) is
studioapi_SetRenderModel. The accessor must write exactly one writable
global and read none; that global is r_model (validated 2026-09-10:
hl-10210 hw.dll 0x101F3D30 -> 0x104EA08C, hl-10210 hw.so 0xC63C0 ->
0x320FD4, hl-8684 hw.dll 0x1D88270 -> 0x235AA58, hl-3248 0x1D92920 ->
0x2435490, cof-5936 0x1DC3B8B -> 0x2431550; r_model is referenced by 8-9
functions per binary). The tiny accessor needs the across-boundary
signature window; SvEngine ships a different diagnostic wording and is
covered by find-studioapi_SetRenderModel-svencoop instead.
"""

from ida_preprocessor_scripts._studio_player_model_common import (
    HL_STUDIO_STRING,
    SLOT_SHAPE_WRITE,
    preprocess_studio_slot,
)

TARGET_FUNC_NAME = "studioapi_SetRenderModel"
TARGET_GV_NAMES = ("r_model",)
SLOT_OFFSET = 0x90
SLOT_SHAPE = SLOT_SHAPE_WRITE


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
        slot_offset=SLOT_OFFSET,
        shape=SLOT_SHAPE,
        gv_names=TARGET_GV_NAMES,
        studio_string=HL_STUDIO_STRING,
        debug=debug,
    )
