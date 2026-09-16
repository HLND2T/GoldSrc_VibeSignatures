#!/usr/bin/env python3
"""Locate R_SetupGL from its verified overview projection constants."""

from ida_analyze_util import preprocess_common_skill


TARGET_FUNC_NAME = "R_SetupGL"
FUNC_XREFS = [
    {
        "func_name": TARGET_FUNC_NAME,
        "xref_floats": ["4096.0", "16000.0"],
    }
]
FUNC_FIELDS = ["func_name", "func_sig", "func_va", "func_rva", "func_size"]


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
    return await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=None,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_names=[TARGET_FUNC_NAME],
        func_xrefs=FUNC_XREFS,
        generate_yaml_desired_fields=[(TARGET_FUNC_NAME, FUNC_FIELDS)],
        debug=debug,
    )
