#!/usr/bin/env python3
"""Locate studioapi_GetCurrentEntity and currententity on SvEngine (svencoop-*).

Same engine_studio_api slot-0x18 chain as the generic finder, but SvEngine
words the ClientDLL_CheckStudioInterface diagnostic differently. Its Linux
build is PIC: the table VA comes from lea reg, [ebx + disp32] with the ebx
GOT anchor recovered from the call-thunk/add-ebx prologue, while the
accessor itself loads currententity through an eax-anchored GOTOFF lea
(validated 2026-09-10: hw.dll 0x1D92820 -> 0x3F94150, hw.so 0x9FAE0 ->
dword_30F6F78). Linux may also have two string owners; the locator
collapses on the unique table VA instead of the owner.
"""

from ida_preprocessor_scripts._studio_player_model_common import (
    SLOT_SHAPE_READ,
    SVC_STUDIO_STRING,
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
        studio_string=SVC_STUDIO_STRING,
        debug=debug,
    )
