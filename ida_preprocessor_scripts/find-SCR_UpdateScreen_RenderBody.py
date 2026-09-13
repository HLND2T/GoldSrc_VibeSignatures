#!/usr/bin/env python3
"""Locate SCR_UpdateScreen_RenderBody, the screen-update rendering body.

``load failed.`` is printed by the actual per-frame rendering body after the
loading plaque check (engine/gl_screen.c SCR_UpdateScreen). Windows resolves to
the full SCR_UpdateScreen; Linux may resolve to a compiler-split body such as
SCR_UpdateScreen.part.*. Predecessor only: GL_BeginRendering, GL_EndRendering
and GL_Finish2D are mined from this body.
"""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = ["SCR_UpdateScreen_RenderBody"]
FUNC_XREFS = [
    {
        "func_name": "SCR_UpdateScreen_RenderBody",
        "xref_strings": ["FULLMATCH:load failed.\n"],
        "xref_gvs": [],
        "xref_signatures": [],
        "xref_funcs": [],
    },
]
GENERATE_YAML_DESIRED_FIELDS = [
    ("SCR_UpdateScreen_RenderBody", ["func_name", "func_sig", "func_va", "func_rva", "func_size"]),
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
