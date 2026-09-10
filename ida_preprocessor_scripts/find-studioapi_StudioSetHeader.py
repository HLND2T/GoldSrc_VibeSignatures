#!/usr/bin/env python3
"""Locate studioapi_StudioSetHeader and pstudiohdr (GoldSrc/HL25/CoF).

ClientDLL_CheckStudioInterface's interface-mismatch diagnostic is unique;
its body passes &engine_studio_api to the client studio interface, and the
table's fixed ABI slot 0x8C (common/r_studioint.h) is
studioapi_StudioSetHeader. The accessor must write exactly one writable
global and read none; that global is pstudiohdr (validated 2026-09-10:
hl-10210 hw.dll 0x101F3D20 -> 0x104D1BF8, hl-10210 hw.so 0xC63B0 ->
0x3378C0, hl-8684 hw.dll 0x1D88260 -> 0x23B64E0, hl-3248 0x1D92910 ->
0x24849C0, cof-5936 0x1DC3B7E -> 0x248CFE4; pstudiohdr is referenced by
27-32 functions per binary, separating it from the adjacent 0x90 slot's
r_model). The tiny accessor needs the across-boundary signature window;
SvEngine ships a different diagnostic wording and is covered by
find-studioapi_StudioSetHeader-svencoop instead.
"""

from ida_preprocessor_scripts._studio_player_model_common import (
    HL_STUDIO_STRING,
    SLOT_SHAPE_WRITE,
    preprocess_studio_slot,
)

TARGET_FUNC_NAME = "studioapi_StudioSetHeader"
TARGET_GV_NAMES = ("pstudiohdr",)
SLOT_OFFSET = 0x8C
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
