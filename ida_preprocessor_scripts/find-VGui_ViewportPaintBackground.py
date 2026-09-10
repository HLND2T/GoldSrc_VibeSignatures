#!/usr/bin/env python3
"""Read cl_enginefuncs SDK slot 78 and resolve its viewport callback shim."""

from ida_preprocessor_scripts._engine_public_callback_common import preprocess_engine_callback


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
    _ = skill_name, old_yaml_map, debug
    return await preprocess_engine_callback(
        session,
        expected_outputs,
        new_binary_dir,
        platform,
        image_base,
        name="VGui_ViewportPaintBackground",
        slot=78,
    )
