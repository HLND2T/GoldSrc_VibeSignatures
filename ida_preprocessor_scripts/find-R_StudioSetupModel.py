#!/usr/bin/env python3
"""Locate the private R_StudioSetupModel, excluding studioapi_SetupModel.

The diagnostic ``R_StudioSetupModel: no such bodypart %d\\n`` lives in
R_StudioSetupModel (engine/r_studio.c). GoldSrc/HL25 Linux also inlines
that body into engine_studio_api slot 20 (studioapi_SetupModel), so the
finder loads that wrapper artifact and excludes it. Windows keeps a
distinct callee; SvEngine Linux is inlined and then has no remaining
owner (do not register this skill on that platform).
"""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = ["R_StudioSetupModel"]
FUNC_XREFS = [
    {
        "func_name": "R_StudioSetupModel",
        "xref_strings": ["FULLMATCH:R_StudioSetupModel: no such bodypart %d\n"],
        "xref_gvs": [],
        "xref_signatures": [],
        "xref_funcs": [],
        "exclude_funcs": ["studioapi_SetupModel"],
        "exclude_strings": [],
        "exclude_gvs": [],
        "exclude_signatures": [],
    },
]
GENERATE_YAML_DESIRED_FIELDS = [
    ("R_StudioSetupModel", ["func_name", "func_sig", "func_va", "func_rva", "func_size"]),
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
