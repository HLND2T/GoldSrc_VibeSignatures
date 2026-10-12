#!/usr/bin/env python3
"""Locate sound initialization through its owned FMOD version diagnostic.

The exact literal has one owner in all four Sven client binaries. That owner
creates the Sfx/Music channel groups and registers cl_spectrum_debug. The
shared string helper handles stripped GCC GOTOFF references without old YAML.
"""

from ida_preprocessor_scripts._sven_client_pic_common import preprocess_string_owner_skill_with_pic_fallback

TARGET_FUNCTION_NAMES = ["CClient_SoundEngine_Initialize"]
LITERAL = (
    'You are using an old version of FMOD: "%08x".  This program requires "%08x"\n\n'
    " Please obtain the correct FMODEx library file or re-install Sven Co-op."
)


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
    return await preprocess_string_owner_skill_with_pic_fallback(
        session, expected_outputs, new_binary_dir, platform, image_base, TARGET_FUNCTION_NAMES[0], LITERAL, debug
    )
