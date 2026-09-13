#!/usr/bin/env python3
"""Locate Draw_DecalTexture through its custom-decal fallback literal.

engine/cl_main.c falls back to the default decal after
``Failed to load custom decal for player #%i:%s using default decal 0.``; the
literal belongs to the decal-texture loader Draw_DecalTexture only.
"""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = ["Draw_DecalTexture"]
FUNC_XREFS = [
    {
        "func_name": "Draw_DecalTexture",
        "xref_strings": ["FULLMATCH:Failed to load custom decal for player #%i:%s using default decal 0.\n"],
        "xref_gvs": [],
        "xref_signatures": [],
        "xref_funcs": [],
    },
]
GENERATE_YAML_DESIRED_FIELDS = [
    ("Draw_DecalTexture", ["func_name", "func_sig", "func_va", "func_rva", "func_size"]),
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
