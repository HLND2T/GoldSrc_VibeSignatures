#!/usr/bin/env python3
"""Locate GL_SetMode through its per-family initialization-failure literals.

Non-SvEngine builds report MSAA framebuffer initialization failure from
GL_SetMode (engine/vid_common.cpp); SvEngine instead fails through its
GLEW bootstrap diagnostic. Each literal has exactly one owner, GL_SetMode,
on its validated builds, so the two specs are tried in order and the first
single-owner match wins.
"""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = ["GL_SetMode"]
FUNC_XREFS_SPECS = [
    [
        {
            "func_name": "GL_SetMode",
            "xref_strings": ["FULLMATCH:Error initializing MSAA frame buffer\n"],
            "xref_gvs": [],
            "xref_signatures": [],
            "xref_funcs": [],
        },
    ],
    [
        {
            "func_name": "GL_SetMode",
            "xref_strings": ["FULLMATCH:GL_SetMode::glewInit() err = %i\n"],
            "xref_gvs": [],
            "xref_signatures": [],
            "xref_funcs": [],
        },
    ],
]
GENERATE_YAML_DESIRED_FIELDS = [
    ("GL_SetMode", ["func_name", "func_sig", "func_va", "func_rva", "func_size"]),
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
    for func_xrefs in FUNC_XREFS_SPECS:
        if await preprocess_common_skill(
            session=session,
            expected_outputs=expected_outputs,
            old_yaml_map=None,
            new_binary_dir=new_binary_dir,
            platform=platform,
            image_base=image_base,
            func_names=TARGET_FUNCTION_NAMES,
            func_xrefs=func_xrefs,
            generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
            debug=debug,
        ):
            return True
    return False
