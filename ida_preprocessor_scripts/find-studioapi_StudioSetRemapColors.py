#!/usr/bin/env python3
"""Locate studioapi_StudioSetRemapColors, r_topcolor and r_bottomcolor.

ClientDLL_CheckStudioInterface's interface-mismatch diagnostic is unique; its
body passes &engine_studio_api to the client studio interface, and the table's
fixed ABI slot 0x78 (common/r_studioint.h, immediately before
studioapi_SetupPlayerModel at 0x7C) is studioapi_StudioSetRemapColors. The
accessor stores the two int parameters in source order: r_topcolor = top,
then r_bottomcolor = bottom. Those stores are recovered in instruction
order; clustering or VA-sorting swaps or collapses them when the objects
are adjacent or laid out in reverse. Validated 2026-09-21: hl-10210 hw.dll
0x101F3CA0 -> 0x104F0EE4/0x1050F6E8, hw.so 0xC6370 -> 0x300D44/0x300D40
(ELF names; VA reversed), hl-8684 hw.so 0x129D30 -> 0x322FF0/0x323000
(16-byte gap), svencoop-10257 hw.dll 0x1D92C20 -> 0x8DFA97C/0x8E13D80,
hw.so 0x9FDF0 -> 0xD01244/0xD01240 (eax GOTOFF, gv_pic_addend 0x2EE000),
cof-5936 0x1DC3B14 -> 0x248B59C/0x242F94C (VA reversed), hl-3248
hw.decrypt.dll 0x1D92890 -> 0x2482F70/0x2433888 (VA reversed). The finder
tries both GoldSrc/HL25/CoF and SvEngine diagnostics.
"""

from ida_preprocessor_scripts._studio_player_model_common import (
    HL_STUDIO_STRING,
    SLOT_SHAPE_WRITE_PAIR,
    SVC_STUDIO_STRING,
    preprocess_studio_slot,
)

TARGET_FUNC_NAME = "studioapi_StudioSetRemapColors"
TARGET_GV_NAMES = ("r_topcolor", "r_bottomcolor")
SLOT_OFFSET = 0x78


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
            shape=SLOT_SHAPE_WRITE_PAIR,
            gv_names=TARGET_GV_NAMES,
            studio_string=studio_string,
            debug=debug,
        ):
            return True
    return False
