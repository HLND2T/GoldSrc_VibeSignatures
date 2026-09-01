#!/usr/bin/env python3
"""Preprocess script for find-CL_PrecacheResources."""

from pathlib import Path

from ida_analyze_util import preprocess_common_skill


TARGET_FUNCTION_NAMES = ["CL_PrecacheResources"]
FUNC_XREFS = [
    {
        "func_name": "CL_PrecacheResources",
        "xref_strings": ["#GameUI_PrecachingResources"],
        "xref_gvs": [],
        "xref_signatures": [],
        "xref_funcs": [],
        "exclude_funcs": [],
        "exclude_strings": [],
        "exclude_gvs": [],
        "exclude_signatures": [],
    },
]
SVENCOOP_FUNC_XREFS = [
    {
        "func_name": "CL_PrecacheResources",
        # The #GameUI_PrecachingResources reference is Sven's function entry and
        # has multiple callers, so use the unique in-function diagnostic string.
        "xref_strings": ["FULLMATCH:begin CL_PrecacheResources()"],
        "xref_gvs": [],
        "xref_signatures": [],
        "xref_funcs": [],
        "exclude_funcs": [],
        "exclude_strings": [],
        "exclude_gvs": [],
        "exclude_signatures": [],
    },
]
GENERATE_YAML_DESIRED_FIELDS = [
    ("CL_PrecacheResources", ["func_name", "func_sig", "func_va", "func_rva", "func_size"]),
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
    func_xrefs = SVENCOOP_FUNC_XREFS if Path(new_binary_dir).parent.name == "svencoop-10257" else FUNC_XREFS
    return await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=None,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_names=TARGET_FUNCTION_NAMES,
        func_xrefs=func_xrefs,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )
