#!/usr/bin/env python3
"""Find TextImage's wide SetText through RTTI and narrow-to-wide buffer flow.

The char overload recognizes '#', converts its input to a local Unicode buffer,
and dispatches that buffer on the same TextImage. Decode the current table slot
and validate the wide copy/ABI. GCC guarded devirtualization is valid evidence;
the slot order, wchar_t width and SDK's optional bool are never assumed.
"""

from ida_preprocessor_scripts._career_bot_cost_common import preprocess_textimage


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
    return await preprocess_textimage(session, expected_outputs, platform, image_base, debug)
