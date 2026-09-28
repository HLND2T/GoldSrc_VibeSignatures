#!/usr/bin/env python3
"""Locate Sven client's IN_Accumulate through its public PE/ELF export."""

from ida_preprocessor_scripts._sven_mouse_exports import preprocess_export

TARGET_FUNCTION_NAMES = ["IN_Accumulate"]


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
    _ = skill_name, old_yaml_map, new_binary_dir
    return await preprocess_export(session, expected_outputs, platform, image_base, TARGET_FUNCTION_NAMES[0], debug)
