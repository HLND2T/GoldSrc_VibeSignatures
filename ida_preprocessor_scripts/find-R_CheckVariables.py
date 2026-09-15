#!/usr/bin/env python3
"""Locate R_CheckVariables through its unique GL_LoadFilterTexture call.

engine/gl_rmisc.c R_CheckVariables is the only engine function that calls
GL_LoadFilterTexture (filter cvar change detection), so the resolved
GL_LoadFilterTexture artifact's unique direct caller is R_CheckVariables.
SvEngine's Linux build inlines that call; that platform is excluded through
config-level platform gating instead of a weaker anchor.
"""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = ["R_CheckVariables"]
FUNC_XREFS = [
    {
        "func_name": "R_CheckVariables",
        "xref_strings": [],
        "xref_gvs": [],
        "xref_signatures": [],
        "xref_funcs": ["GL_LoadFilterTexture"],
    },
]
GENERATE_YAML_DESIRED_FIELDS = [
    ("R_CheckVariables", ["func_name", "func_sig", "func_va", "func_rva", "func_size"]),
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
