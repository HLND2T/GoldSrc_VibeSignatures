#!/usr/bin/env python3
"""Locate studioapi_SetForceFaceFlags (GoldSrc/HL25/CoF/SvEngine).

Same engine_studio_api chain as find-studioapi_GetForceFaceFlags: the unique
ClientDLL_CheckStudioInterface diagnostic anchors the table, and fixed ABI slot
0x88 (common/r_studioint.h, immediately after GetForceFaceFlags at 0x84) is
studioapi_SetForceFaceFlags. The accessor's only global access is the store of
its int parameter, so the write_only shape gate requires exactly one
writable-data store base and no read base. That store target must be the same
address the slot-0x84 accessor reads; the Getter finder owns the
g_ForcedFaceFlags artifact, so this finder deliberately emits the function only.

Validated 2026-09-24 on every configured engine build with the production
locator (table segment .data, code-pointer run 45; Set slot -> store target):
hl-3248 hw.decrypt.dll 0x1D92900 -> 0x246E238, hl-3266 0x1D928E0 -> 0x246E238,
hl-3329 0x1D927C0 -> 0x243B0E0, hl-3647 0x1D92930 -> 0x2439F88, hl-4554
0x1D9E8B0 -> 0x24242C8, hl-6153 0x1D868D0 -> 0x23902E8, hl-8684 hw.dll
0x1D88250 -> 0x2393808 and hw.so 0x129D60 -> 0x322FE0, hl-10210 hw.dll
0x101F3D10 -> 0x104EA094 and hw.so 0xC63A0 -> 0x320FCC, cof-5936 0x1DC3B71 ->
0x246A318, svencoop-8948 hw.dll 0x1D91D40 -> 0x8DB39A4 and hw.so 0xEE920 ->
0xD73E8C, svencoop-10257 hw.dll 0x1D92C90 -> 0x8DF3B2C and hw.so 0x9FE30 ->
0xD268CC. The tiny accessor has no unique strict-window signature, so the
artifact carries func_sig_allow_across_function_boundary.
"""

from ida_preprocessor_scripts._studio_player_model_common import (
    HL_STUDIO_STRING,
    SLOT_SHAPE_WRITE_NO_GV,
    SVC_STUDIO_STRING,
    preprocess_studio_slot,
)

TARGET_FUNC_NAME = "studioapi_SetForceFaceFlags"
SLOT_OFFSET = 0x88


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
            shape=SLOT_SHAPE_WRITE_NO_GV,
            gv_names=(),
            studio_string=studio_string,
            debug=debug,
        ):
            return True
    return False
