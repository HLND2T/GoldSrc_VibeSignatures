#!/usr/bin/env python3
"""Locate the client model lookup through its own precache timing diagnostic.

engine/cl_main.c's CL_GetModelByIndex reads cl.model_precache[index], lazily
loads brush/sprite models, and prints this exact diagnostic. The table is a
client_state_t member, not mod_known or a standalone global. The full literal
has one owner on both Sven builds/platforms; the cvar name alone is ambiguous.
"""

from ida_preprocessor_scripts._sven_client_pic_common import preprocess_string_owner_skill_with_pic_fallback

TARGET_FUNCTION_NAMES = ["CL_GetModelByIndex"]
LITERAL = "fs_precache_timings: loaded model %s in time %.3f sec\n"


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
    return await preprocess_string_owner_skill_with_pic_fallback(
        session, expected_outputs, new_binary_dir, platform, image_base, TARGET_FUNCTION_NAMES[0], LITERAL, debug
    )
