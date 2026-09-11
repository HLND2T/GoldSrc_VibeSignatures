#!/usr/bin/env python3
"""Read svc_setview's handler, which receives cl.viewentity from the server."""

from ida_preprocessor_scripts._svc_callback_common import preprocess_svc_callback


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
    return await preprocess_svc_callback(
        session,
        expected_outputs,
        new_binary_dir,
        platform,
        image_base,
        name="CL_Parse_SetView",
        service="svc_setview",
    )
