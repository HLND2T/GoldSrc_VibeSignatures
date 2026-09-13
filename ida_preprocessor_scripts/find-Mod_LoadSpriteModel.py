#!/usr/bin/env python3
"""Locate Mod_LoadSpriteModel through its per-family sprite-load literals.

Non-SvEngine builds reject a bad sprite frame count with ``Mod_LoadSpriteModel:
Invalid # of frames`` (engine/mod loading), while SvEngine instead reports
``Sprite "%s" has wrong version number (%i should be %i)`` from its rewritten
sprite loader. Each literal has exactly one owner, Mod_LoadSpriteModel, on its
validated builds, so the two specs are tried in order and the first
single-owner match wins.
"""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = ["Mod_LoadSpriteModel"]
FUNC_XREFS_SPECS = [
    [
        {
            "func_name": "Mod_LoadSpriteModel",
            "xref_strings": ["FULLMATCH:Mod_LoadSpriteModel: Invalid # of frames: %d\n"],
            "xref_gvs": [],
            "xref_signatures": [],
            "xref_funcs": [],
        },
    ],
    [
        {
            "func_name": "Mod_LoadSpriteModel",
            "xref_strings": ['FULLMATCH:Sprite "%s" has wrong version number (%i should be %i)'],
            "xref_gvs": [],
            "xref_signatures": [],
            "xref_funcs": [],
        },
    ],
]
GENERATE_YAML_DESIRED_FIELDS = [
    ("Mod_LoadSpriteModel", ["func_name", "func_sig", "func_va", "func_rva", "func_size"]),
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
