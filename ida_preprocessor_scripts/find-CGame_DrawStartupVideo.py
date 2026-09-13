#!/usr/bin/env python3
"""Locate CGame_DrawStartupVideo through its WebM player literal.

HL25 plays the startup WebM through WebMPlayer::PlayVideo, aliased here as
CGame_DrawStartupVideo (MetaHook DRAWSTARTUPVIDEO_HL25 role). The function is
the single owner of ``WebMPlayer::PlayVideo %s``; HL25 Windows/Linux only.
"""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = ["CGame_DrawStartupVideo"]
FUNC_XREFS = [
    {
        "func_name": "CGame_DrawStartupVideo",
        "xref_strings": ["FULLMATCH:WebMPlayer::PlayVideo %s\n"],
        "xref_gvs": [],
        "xref_signatures": [],
        "xref_funcs": [],
    },
]
GENERATE_YAML_DESIRED_FIELDS = [
    ("CGame_DrawStartupVideo", ["func_name", "func_sig", "func_va", "func_rva", "func_size"]),
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
