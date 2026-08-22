#!/usr/bin/env python3
"""Preprocess script for find-Cvar_DirectSet."""

from ida_analyze_util import preprocess_common_skill


TARGET_FUNCTION_NAMES = ["Cvar_DirectSet"]

FUNC_XREFS = [
    {
        "func_name": "Cvar_DirectSet",
        "xref_strings": ["FULLMATCH:***PROTECTED***"],
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
    ("Cvar_DirectSet", ["func_name", "func_sig", "func_va", "func_rva", "func_size"]),
]
EXTENDED_SIGNATURE_DESIRED_FIELDS = [
    (
        "Cvar_DirectSet",
        [
            "func_name",
            "func_sig",
            "func_va",
            "func_rva",
            "func_size",
            "func_sig_allow_across_function_boundary:true",
        ],
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
    _ = skill_name
    common_arguments = {
        "session": session,
        "expected_outputs": expected_outputs,
        "old_yaml_map": None,
        "new_binary_dir": new_binary_dir,
        "platform": platform,
        "image_base": image_base,
        "func_names": TARGET_FUNCTION_NAMES,
        "func_xrefs": FUNC_XREFS,
        "debug": debug,
    }
    if await preprocess_common_skill(
        **common_arguments,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
    ):
        return True
    return await preprocess_common_skill(
        **common_arguments,
        generate_yaml_desired_fields=EXTENDED_SIGNATURE_DESIRED_FIELDS,
    )
