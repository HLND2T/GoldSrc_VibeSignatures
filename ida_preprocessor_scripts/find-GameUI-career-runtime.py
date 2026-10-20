#!/usr/bin/env python3
"""Recover the minimal preflight/input boundaries for Windows hl-10210."""

from ida_preprocessor_scripts._career_runtime_common import preprocess_runtime


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
    return await preprocess_runtime(session, expected_outputs, new_binary_dir, platform, image_base, debug)
