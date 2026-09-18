#!/usr/bin/env python3
"""Recover cl_waterlevel and cl_simorg through V_SetRefParams semantics."""

from ida_preprocessor_scripts._renderer_private_globals_common import (
    preprocess_ref_params_globals,
)


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
    return await preprocess_ref_params_globals(
        session,
        expected_outputs,
        new_binary_dir,
        platform,
        image_base,
        debug=debug,
    )
