#!/usr/bin/env python3
"""Locate studioapi_GetForceFaceFlags and g_ForcedFaceFlags (GoldSrc/HL25/CoF/SvEngine).

ClientDLL_CheckStudioInterface's interface-mismatch diagnostic is unique; its
body passes &engine_studio_api to the client studio interface, and the table's
fixed ABI slot 0x84 (common/r_studioint.h, between StudioClientEvents at 0x80
and SetForceFaceFlags at 0x88) is studioapi_GetForceFaceFlags. The accessor is
a one-load stub returning g_ForcedFaceFlags, so the shape gate requires exactly
one writable-data read base and no write base; that load's disp32 operand is
the global. The sibling find-studioapi_SetForceFaceFlags validates slot 0x88
stores that same address, which is the independent role cross-check.

Validated 2026-09-24 on every configured engine build with the production
locator (table segment .data, code-pointer run 45; Get slot -> global):
hl-3248 hw.decrypt.dll 0x1D928F0 -> 0x246E238, hl-3266 0x1D928D0 -> 0x246E238,
hl-3329 0x1D927B0 -> 0x243B0E0, hl-3647 0x1D92920 -> 0x2439F88, hl-4554
0x1D9E8A0 -> 0x24242C8, hl-6153 0x1D868C0 -> 0x23902E8, hl-8684 hw.dll
0x1D88240 -> 0x2393808 and hw.so 0x129D50 -> 0x322FE0, hl-10210 hw.dll
0x101F3D00 -> 0x104EA094 and hw.so 0xC6390 -> 0x320FCC, cof-5936 0x1DC3B67 ->
0x246A318, svencoop-8948 hw.dll 0x1D91D30 -> 0x8DB39A4 and hw.so 0xEE900 ->
0xD73E8C (eax GOTOFF, gv_pic_addend 0x33A000), svencoop-10257 hw.dll 0x1D92C80
-> 0x8DF3B2C and hw.so 0x9FE10 -> 0xD268CC (gv_pic_addend 0x2EE000). The IDB's
restored engine_studio_api_t names both slots GetForceFaceFlags/SetForceFaceFlags
(hl-10210/hl-8684 hw.so), and SvEngine's Linux ELF symbol for the global is the
file-static _ZL17g_ForcedFaceFlags. The tiny accessor has no unique strict-window
signature, so the artifact carries func_sig_allow_across_function_boundary.
"""

from ida_preprocessor_scripts._studio_player_model_common import (
    HL_STUDIO_STRING,
    SLOT_SHAPE_READ,
    SVC_STUDIO_STRING,
    preprocess_studio_slot,
)

TARGET_FUNC_NAME = "studioapi_GetForceFaceFlags"
TARGET_GV_NAMES = ("g_ForcedFaceFlags",)
SLOT_OFFSET = 0x84


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
            shape=SLOT_SHAPE_READ,
            gv_names=TARGET_GV_NAMES,
            studio_string=studio_string,
            debug=debug,
        ):
            return True
    return False
