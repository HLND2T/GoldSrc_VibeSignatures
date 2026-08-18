#!/usr/bin/env python3
"""Preprocess script for find-NLoadBlob."""

from ida_analyze_util import preprocess_common_skill


TARGET_FUNCTION_NAMES = ["NLoadBlob"]

FUNC_XREFS = [
    {
        "func_name": "NLoadBlob",
        "xref_strings": [],
        "xref_gvs": [],
        "xref_signatures": ["85 BC 32 7A", "6A 00 6A 01 6A 00"],
        "xref_funcs": [],
        "exclude_funcs": [],
        "exclude_strings": [],
        "exclude_gvs": [],
        "exclude_signatures": [],
    },
]

GENERATE_YAML_DESIRED_FIELDS = [
    ("NLoadBlob", ["func_name", "func_sig", "func_va", "func_rva", "func_size"]),
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
