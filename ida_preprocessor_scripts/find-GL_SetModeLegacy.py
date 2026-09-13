#!/usr/bin/env python3
"""Locate GL_SetModeLegacy through its GL-driver bootstrap failure literal.

Legacy pre-SDL builds abort GL mode selection when the opengl32.dll driver
cannot be loaded; the diagnostic has exactly one owner, GL_SetModeLegacy
(engine/vid_common.cpp GL_SetMode), on every validated legacy branch.
"""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = ["GL_SetModeLegacy"]
FUNC_XREFS = [
    {
        "func_name": "GL_SetModeLegacy",
        "xref_strings": ["FULLMATCH:Error initializing gl driver, check that the GL driver file opengl32.dll exists"],
        "xref_gvs": [],
        "xref_signatures": [],
        "xref_funcs": [],
    },
]
GENERATE_YAML_DESIRED_FIELDS = [
    ("GL_SetModeLegacy", ["func_name", "func_sig", "func_va", "func_rva", "func_size"]),
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
