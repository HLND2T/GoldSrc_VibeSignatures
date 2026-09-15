#!/usr/bin/env python3
"""Locate GL_SelectPixelFormat through its pixel-format failure literals.

The Windows legacy GL startup path (engine/gl_vidnt.c bSetupPixelFormat) reports
ChoosePixelFormat/SetPixelFormat failures through MessageBox literals that only
this function owns. HL25 inlines the selection into GL_SetMode (the literal's
owner becomes GL_SetMode itself) and SvEngine uses wgl*ARB/EXT instead, so this
finder is only registered on the legacy Windows engine builds.

Discovery is a single exact-match string anchor; no byte signature or old YAML
is used for locating.
"""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = ["GL_SelectPixelFormat"]
FUNC_XREFS = [
    {
        "func_name": "GL_SelectPixelFormat",
        "xref_strings": ["FULLMATCH:ChoosePixelFormat failed"],
        "xref_gvs": [],
        "xref_signatures": [],
        "xref_funcs": [],
    },
]
GENERATE_YAML_DESIRED_FIELDS = [
    ("GL_SelectPixelFormat", ["func_name", "func_sig", "func_va", "func_rva", "func_size"]),
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
