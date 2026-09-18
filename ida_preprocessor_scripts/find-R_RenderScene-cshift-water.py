#!/usr/bin/env python3
"""Recover cshift_water through R_SetupFrame fog semantics."""

from ida_preprocessor_scripts._renderer_private_globals_common import preprocess_cshift_water


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
    return await preprocess_cshift_water(
        session,
        expected_outputs,
        new_binary_dir,
        platform,
        image_base,
        predecessor="R_RenderScene",
        debug=debug,
    )
