#!/usr/bin/env python3
"""Locate the Sven Co-op client portal invisible-texture creator.

The portal manager allocates the shared invisible portal texture and reports
"Invalid GL_ACTIVE_TEXTURE, unable to reset. Couldn't create invisible
texture for portals." when the active-texture unit cannot be restored. The
literal has exactly one function owner on the validated 10257 client, and
that creator has exactly one caller - ClientPortalManager::ResetAll - so
find-ClientPortalManager_ResetAll consumes this artifact as its anchor.
"""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = ["ClientPortalManager_CreateInvisiblePortalTextures"]
FUNC_XREFS = [
    {
        "func_name": "ClientPortalManager_CreateInvisiblePortalTextures",
        "xref_strings": [
            "FULLMATCH:Invalid GL_ACTIVE_TEXTURE, unable to reset. Couldn't create invisible texture for portals.\n"
        ],
        "xref_gvs": [],
        "xref_signatures": [],
        "xref_funcs": [],
    },
]
GENERATE_YAML_DESIRED_FIELDS = [
    (
        "ClientPortalManager_CreateInvisiblePortalTextures",
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
