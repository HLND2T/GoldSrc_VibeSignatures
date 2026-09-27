#!/usr/bin/env python3
"""Locate WeaponsResource_SelectSlot in the Sven Co-op client.

WeaponsResource::SelectSlot(int, bool, int) plays this sound when opening a
weapon slot. D:/HLND2T_official/cl_dll/ammo.cpp documents the equivalent
selection path; the Sven 8948 ELF supplies the actual bool-argument ABI.
The literal has one owner on Sven 8948/10257, Windows/Linux. Registration is
limited to the approved Sven client scope.

Reuse the existing exact-string owner locator, including its Linux PIC
fallback. Discovery never uses a prior artifact; the generated signature
is validated only after the owner has been recovered.
"""

from ida_preprocessor_scripts._sven_client_pic_common import (
    preprocess_string_owner_skill_with_pic_fallback,
)

TARGET_FUNCTION_NAMES = ["WeaponsResource_SelectSlot"]
LITERAL = "common/wpn_hudon.wav"


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
    return await preprocess_string_owner_skill_with_pic_fallback(
        session,
        expected_outputs=expected_outputs,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_name=TARGET_FUNCTION_NAMES[0],
        literal=LITERAL,
        debug=debug,
    )
