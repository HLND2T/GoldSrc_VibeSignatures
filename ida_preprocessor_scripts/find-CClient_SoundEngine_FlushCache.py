#!/usr/bin/env python3
"""Locate the callable Sven sound-list disk-cache flush method.

The target-owned diagnostic has one owner on 8948/10257 Windows/Linux.
Windows x86: void __thiscall(void *this, bool all), byte argument in a
four-byte stack slot, ret 4. Linux i386: void __cdecl(void *this, bool all).
The method does not use this, but retains the member-function ABI. Passing
false preserves the current map/server list; true bypasses that protection.
This does not clear the in-memory sound arrays or replace the download/retry
recovery in LoadSoundList. No prior artifact participates in discovery.
"""

from ida_preprocessor_scripts._sven_client_pic_common import preprocess_string_owner_skill_with_pic_fallback

TARGET_FUNCTION_NAMES = ["CClient_SoundEngine_FlushCache"]
LITERAL = "Flushing cached sound list files...\n"


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
    return await preprocess_string_owner_skill_with_pic_fallback(
        session, expected_outputs, new_binary_dir, platform, image_base, TARGET_FUNCTION_NAMES[0], LITERAL, debug
    )
