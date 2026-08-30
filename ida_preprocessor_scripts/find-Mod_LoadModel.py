#!/usr/bin/env python3
"""Preprocess script for find-Mod_LoadModel."""

from ida_analyze_util import preprocess_common_skill


TARGET_FUNCTION_NAMES = ["Mod_LoadModel"]

# GoldSrc/CoF and SvEngine use different diagnostics in the loading body.  On
# optimized Linux GoldSrc builds this body is Mod_LoadModel.part.N, which is the
# required control-flow root; the public Mod_LoadModel symbol is only a wrapper.
FUNC_XREF_ALTERNATIVES = [
    [
        {
            "func_name": "Mod_LoadModel",
            "xref_strings": ["FULLMATCH:Mod_NumForName: %s not found"],
            "xref_gvs": [],
            "xref_signatures": [],
            "xref_funcs": [],
            "exclude_funcs": [],
            "exclude_strings": [],
            "exclude_gvs": [],
            "exclude_signatures": [],
        },
    ],
    [
        {
            "func_name": "Mod_LoadModel",
            "xref_strings": ["FULLMATCH:Mod_LoadModel: Could not load '%s': File not found"],
            "xref_gvs": [],
            "xref_signatures": [],
            "xref_funcs": [],
            "exclude_funcs": [],
            "exclude_strings": [],
            "exclude_gvs": [],
            "exclude_signatures": [],
        },
    ],
]

GENERATE_YAML_DESIRED_FIELDS = [
    ("Mod_LoadModel", ["func_name", "func_sig", "func_va", "func_rva", "func_size"]),
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
    for func_xrefs in FUNC_XREF_ALTERNATIVES:
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
