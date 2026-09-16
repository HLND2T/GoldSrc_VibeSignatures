#!/usr/bin/env python3
"""Locate the Sven Co-op client ClientPortalManager::ResetAll.

ResetAll clears the manager (portal vector, texture maps, cached state) and
recreates the shared invisible portal texture, so it is the unique caller of
the verified ClientPortalManager_CreateInvisiblePortalTextures on the
validated 10257 client, Windows and Linux alike. The function itself owns no
literal (MetaHookSv reaches it through a byte pattern on older builds).
"""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = ["ClientPortalManager_ResetAll"]
FUNC_XREFS = [
    {
        "func_name": "ClientPortalManager_ResetAll",
        "xref_strings": [],
        "xref_gvs": [],
        "xref_signatures": [],
        "xref_funcs": ["ClientPortalManager_CreateInvisiblePortalTextures"],
    },
]
GENERATE_YAML_DESIRED_FIELDS = [
    (
        "ClientPortalManager_ResetAll",
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
    for extend_signature in (False, True):
        fields = [
            (name, desired + (["func_sig_allow_across_function_boundary:true"] if extend_signature else []))
            for name, desired in GENERATE_YAML_DESIRED_FIELDS
        ]
        if await preprocess_common_skill(
            session=session,
            expected_outputs=expected_outputs,
            old_yaml_map=None,
            new_binary_dir=new_binary_dir,
            platform=platform,
            image_base=image_base,
            func_names=TARGET_FUNCTION_NAMES,
            func_xrefs=FUNC_XREFS,
            generate_yaml_desired_fields=fields,
            debug=debug,
        ):
            return True
    return False
