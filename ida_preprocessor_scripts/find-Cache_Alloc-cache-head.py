#!/usr/bin/env python3
"""Recover cache_head from the verified Cache_Alloc sentinel loop."""

from ida_preprocessor_scripts._renderer_private_globals_common import preprocess_cache_head


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
    return await preprocess_cache_head(
        session,
        expected_outputs,
        new_binary_dir,
        platform,
        image_base,
        debug=debug,
    )
