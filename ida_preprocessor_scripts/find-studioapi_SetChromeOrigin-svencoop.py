#!/usr/bin/env python3
"""Locate studioapi_SetChromeOrigin, r_origin and g_ChromeOrigin on SvEngine (svencoop-*).

Same engine_studio_api slot-0x9C chain as the generic finder, but SvEngine
words the ClientDLL_CheckStudioInterface diagnostic differently. The copy
uses x87 fld/fstp on Windows and an eax-anchored GOTOFF prologue on Linux,
where r_origin comes from the GOTOFF lea cluster base and g_ChromeOrigin
from the movss store cluster base (validated 2026-09-10: hw.dll 0x1D929D0
-> 0x3F941D8/0x8DF3B30, hw.so 0x9FC10 -> flt_30F6EE0/dword_D268C0).
Linux may also have two string owners; the locator collapses on the unique
table VA instead of the owner.
"""

from ida_preprocessor_scripts._studio_player_model_common import (
    SLOT_SHAPE_COPY12,
    SVC_STUDIO_STRING,
    preprocess_studio_slot,
)

TARGET_FUNC_NAME = "studioapi_SetChromeOrigin"
TARGET_GV_NAMES = ("r_origin", "g_ChromeOrigin")
SLOT_OFFSET = 0x9C
SLOT_SHAPE = SLOT_SHAPE_COPY12


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
