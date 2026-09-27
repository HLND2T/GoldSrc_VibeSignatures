#!/usr/bin/env python3
"""Locate CClient_SoundEngine_PlayFMODSound in the Sven Co-op client.

CClient_SoundEngine::PlayFMODSound(int, int, float const*, int, char const*,
float, float, int, int, int, float) logs this diagnostic in its music-sample
playback path. The literal has one owner in Sven 8948/10257, Windows/Linux.
The sentence-index diagnostic is not an anchor for this target: that lookup
can also exist as a separate function alongside the inlined playback copy.

Reuse the existing exact-string owner locator, including its Linux PIC
fallback. Discovery never uses a prior artifact; the generated signature
is validated only after the owner has been recovered.
"""

from ida_preprocessor_scripts._sven_client_pic_common import (
    preprocess_string_owner_skill_with_pic_fallback,
)

TARGET_FUNCTION_NAMES = ["CClient_SoundEngine_PlayFMODSound"]
LITERAL = "Playing music sample '%s', offset %f.\n"


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
