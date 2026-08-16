#!/usr/bin/env python3
"""Preprocess script for find-ClientDLL_Init."""

from pathlib import Path

from ida_analyze_util import preprocess_common_skill


TARGET_FUNCTION_NAMES = ["ClientDLL_Init"]
SVENCOOP_WINDOWS_GAMEVER = "svencoop-10257"

FUNC_XREFS = [
    {
        "func_name": "ClientDLL_Init",
        "xref_strings": ["FULLMATCH:ScreenShake"],
        "xref_gvs": [],
        "xref_signatures": [],
        "xref_funcs": [],
        "exclude_funcs": [],
        "exclude_strings": [],
        "exclude_gvs": [],
        "exclude_signatures": [],
    },
]

FUNCTION_FIELDS = ["func_name", "func_sig", "func_va", "func_rva", "func_size"]
GENERATE_YAML_DESIRED_FIELDS = [("ClientDLL_Init", FUNCTION_FIELDS)]
GENERATE_YAML_DESIRED_FIELDS_ACROSS_BOUNDARY = [
    ("ClientDLL_Init", [*FUNCTION_FIELDS, "func_sig_allow_across_function_boundary:true"])
]


def _generate_yaml_desired_fields(new_binary_dir, platform):
    gamever = Path(new_binary_dir).parent.name
    if platform == "windows" and gamever == SVENCOOP_WINDOWS_GAMEVER:
        return GENERATE_YAML_DESIRED_FIELDS_ACROSS_BOUNDARY
    return GENERATE_YAML_DESIRED_FIELDS


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
    _ = skill_name
    return await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=old_yaml_map,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_names=TARGET_FUNCTION_NAMES,
        func_xrefs=FUNC_XREFS,
        generate_yaml_desired_fields=_generate_yaml_desired_fields(new_binary_dir, platform),
        debug=debug,
    )
