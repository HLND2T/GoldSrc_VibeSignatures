#!/usr/bin/env python3
"""Locate SvEngine's outer skybox loader through its desert fallback literal.

The outer SvEngine skybox loader gates on the loading state, clears the six
sky textures, calls the internal loader and falls back to the ``desert``
skybox before filling a missing texture (MetaHookSv gl_hooks.cpp keeps the
same role). On SvEngine Windows the desert literal has exactly one function
owner, R_LoadSkyBox_SvEngine. On Linux the literal is shared by the
parameterized wrapper and an inlined no-argument function, so the Linux
branch uses find-SkyboxCommand-decompiles instead.
"""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = ["R_LoadSkyBox_SvEngine"]
FUNC_XREFS = [
    {
        "func_name": "R_LoadSkyBox_SvEngine",
        "xref_strings": ["FULLMATCH:desert"],
        "xref_gvs": [],
        "xref_signatures": [],
        "xref_funcs": [],
    },
]
GENERATE_YAML_DESIRED_FIELDS = [
    ("R_LoadSkyBox_SvEngine", ["func_name", "func_sig", "func_va", "func_rva", "func_size"]),
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
