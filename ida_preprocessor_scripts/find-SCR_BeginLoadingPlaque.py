#!/usr/bin/env python3
"""Locate SCR_BeginLoadingPlaque by intersecting three exact string owners.

"Connecting", "#GameUI_EstablishingConnection", and "transition" can each
have more than one owner, but their owner-set intersection uniquely identifies
the loading-plaque entry in every supported engine build. Discovery fails
closed if that intersection stops being unique.
"""

from ida_analyze_util import preprocess_common_skill


TARGET_FUNCTION_NAMES = ["SCR_BeginLoadingPlaque"]
FUNC_XREFS = [
    {
        "func_name": "SCR_BeginLoadingPlaque",
        "xref_strings": [
            "FULLMATCH:Connecting",
            "FULLMATCH:#GameUI_EstablishingConnection",
            "FULLMATCH:transition",
        ],
        "xref_gvs": [],
        "xref_signatures": [],
        "xref_funcs": [],
    },
]
GENERATE_YAML_DESIRED_FIELDS = [
    ("SCR_BeginLoadingPlaque", ["func_name", "func_sig", "func_va", "func_rva", "func_size"]),
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
