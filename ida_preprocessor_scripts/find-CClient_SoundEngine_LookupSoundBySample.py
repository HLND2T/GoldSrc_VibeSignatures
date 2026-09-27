#!/usr/bin/env python3
"""Locate CClient_SoundEngine_LookupSoundBySample in the Sven Co-op client.

CClient_SoundEngine::LookupSoundBySample(char const*) rejects a null or empty
sample name before searching the loaded sample table. Its own diagnostic is
unique in both Sven client builds (8948/10257), on Windows and Linux.

Reuse the existing exact-string owner locator, including its Linux PIC
fallback. Discovery never uses a prior artifact; the generated signature
is validated only after the owner has been recovered.
"""

from ida_preprocessor_scripts._sven_client_pic_common import (
    preprocess_string_owner_skill_with_pic_fallback,
)

TARGET_FUNCTION_NAMES = ["CClient_SoundEngine_LookupSoundBySample"]
LITERAL = "Tried to look up sound by sample without specifying a file name.\n"


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
