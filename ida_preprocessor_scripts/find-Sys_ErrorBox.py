#!/usr/bin/env python3
"""Locate Sven Co-op's error box through its console diagnostic."""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = ["Sys_ErrorBox"]
FUNC_XREFS = [
    {
        "func_name": "Sys_ErrorBox",
        "xref_strings": ["FULLMATCH:ERROR: %s\n"],
    },
]
GENERATE_YAML_DESIRED_FIELDS = [
    (
        "Sys_ErrorBox",
        ["func_name", "func_sig", "func_va", "func_rva", "func_size", "func_sig_allow_across_function_boundary:true"],
    ),
]


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
        func_names=TARGET_FUNCTION_NAMES,
        func_xrefs=FUNC_XREFS,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )
