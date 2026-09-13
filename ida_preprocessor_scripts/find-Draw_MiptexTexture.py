#!/usr/bin/env python3
"""Locate Draw_MiptexTexture, the wad-cached miptex draw entry.

Draw_MiptexTexture reports a bad cached wad by name before uploading the
miptex (engine/gl_draw.c). The diagnostic has exactly one owner on every
validated branch. Predecessor only: GL_LoadTexture2 is mined from this
body on the hl-10210 Linux branch.
"""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = ["Draw_MiptexTexture"]
FUNC_XREFS = [
    {
        "func_name": "Draw_MiptexTexture",
        "xref_strings": ["FULLMATCH:Draw_MiptexTexture: Bad cached wad %s\n"],
        "xref_gvs": [],
        "xref_signatures": [],
        "xref_funcs": [],
    },
]
GENERATE_YAML_DESIRED_FIELDS = [
    ("Draw_MiptexTexture", ["func_name", "func_sig", "func_va", "func_rva", "func_size"]),
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
