#!/usr/bin/env python3
"""Locate studioapi_SetChromeOrigin, r_origin and g_ChromeOrigin (GoldSrc/HL25/CoF).

ClientDLL_CheckStudioInterface's interface-mismatch diagnostic is unique;
its body passes &engine_studio_api to the client studio interface, and the
table's fixed ABI slot 0x9C (common/r_studioint.h) is
studioapi_SetChromeOrigin. VectorCopy(r_origin, g_ChromeOrigin) compiles to
one 12-byte read cluster and one 12-byte write cluster across every shipped
encoding: mov pairs, SSE movss (hl-10210), x87 fld/fstp (SvEngine), and
eax-anchored GOTOFF PIC (SvEngine Linux). The read cluster base is r_origin
and the write cluster base is g_ChromeOrigin (validated 2026-09-10:
hl-10210 hw.dll 0x101F3A70 -> 0x10DC5578/0x104EA0A0, hl-8684 0x1D87FA0 ->
0x2BC98F0/0x2358840, hl-3248 0x1D92650 -> 0x2C20230/0x2433278, cof-5936
0x1DC388E -> 0x2C0E4B0/0x242F340; r_origin is referenced by ~20-25
functions, g_ChromeOrigin by 3-4). SvEngine ships a different diagnostic
wording and is covered by find-studioapi_SetChromeOrigin-svencoop instead.
"""

from ida_preprocessor_scripts._studio_player_model_common import (
    HL_STUDIO_STRING,
    SLOT_SHAPE_COPY12,
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
        studio_string=HL_STUDIO_STRING,
        debug=debug,
    )
