#!/usr/bin/env python3
"""Locate the extended server-provided disconnect reason."""

from ida_preprocessor_scripts._disconnection_globals_common import preprocess_disconnection_globals


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
    _ = old_yaml_map
    return await preprocess_disconnection_globals(
        session,
        skill_name,
        expected_outputs,
        new_binary_dir,
        platform,
        image_base,
        owner_name="COM_ExtendedExplainDisconnection",
        reason_name="gszExtendedDisconnectReason",
        include_flag=False,
        debug=debug,
    )
