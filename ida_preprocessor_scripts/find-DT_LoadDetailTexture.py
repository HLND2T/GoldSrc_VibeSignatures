#!/usr/bin/env python3
"""Locate DT_LoadDetailTexture, the SvEngine detail-texture loader.

SvEngine's detail texture path reports the failing texture file by name
(engine/gl_rmisc.c DT_LoadDetailTexture). The diagnostic has exactly one
owner on the validated SvEngine branch. Predecessor only: GL_LoadTexture2
is mined from this body on the svencoop-10257 Linux branch.
"""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = ["DT_LoadDetailTexture"]
FUNC_XREFS = [
    {
        "func_name": "DT_LoadDetailTexture",
        "xref_strings": ["FULLMATCH:Detail texture map load failed: %s\n"],
        "xref_gvs": [],
        "xref_signatures": [],
        "xref_funcs": [],
    },
]
GENERATE_YAML_DESIRED_FIELDS = [
    ("DT_LoadDetailTexture", ["func_name", "func_sig", "func_va", "func_rva", "func_size"]),
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
