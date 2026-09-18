#!/usr/bin/env python3
"""Locate CheckMultiTextureExtensions through its no-extension diagnostic.

engine/gl_vidnt.c CheckMultiTextureExtensions prints
``NO Multitexture extensions found.`` when neither ARB nor SGIS
multitexture is advertised. The literal has exactly one owner on every
validated HL/CoF engine except HL25 Windows, where MSVC inlines the
probe into GL_Init (identical func_va / func_size / func_sig); that
branch is linux-only. SvEngine uses a different diagnostic owned by
InitMultitexturing, so this finder is not registered there.
"""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = ["CheckMultiTextureExtensions"]
FUNC_XREFS = [
    {
        "func_name": "CheckMultiTextureExtensions",
        "xref_strings": ["FULLMATCH:NO Multitexture extensions found.\n"],
        "xref_gvs": [],
        "xref_signatures": [],
        "xref_funcs": [],
    },
]
GENERATE_YAML_DESIRED_FIELDS = [
    (
        "CheckMultiTextureExtensions",
        ["func_name", "func_sig", "func_va", "func_rva", "func_size"],
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
