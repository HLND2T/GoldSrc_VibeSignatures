#!/usr/bin/env python3
"""Locate studioapi_GetCurrentEntity and currententity (GoldSrc/HL25/CoF).

ClientDLL_CheckStudioInterface's interface-mismatch diagnostic is unique;
its body passes &engine_studio_api to the client studio interface, and the
table's fixed ABI slot 0x18 (common/r_studioint.h) is
studioapi_GetCurrentEntity. The accessor must read exactly one writable
global and write none; that global is currententity (validated 2026-09-10:
hl-10210 hw.dll 0x101F3840 -> 0x10DC5618, hl-10210 hw.so 0xC6090 ->
0xF7D930, hl-8684 hw.dll 0x1D87D60 -> 0x2BC98FC, hl-3248 0x1D92430 ->
0x2C2023C, cof-5936 0x1DC3690 -> 0x2C0E4BC; currententity is referenced by
39-47 functions per binary). The tiny accessor needs the across-boundary
signature window; SvEngine ships a different diagnostic wording and is
covered by find-studioapi_GetCurrentEntity-svencoop instead.
"""

from ida_preprocessor_scripts._studio_player_model_common import (
    HL_STUDIO_STRING,
    SLOT_SHAPE_READ,
    preprocess_studio_slot,
)

TARGET_FUNC_NAME = "studioapi_GetCurrentEntity"
TARGET_GV_NAMES = ("currententity",)
SLOT_OFFSET = 0x18
SLOT_SHAPE = SLOT_SHAPE_READ


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
