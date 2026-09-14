#!/usr/bin/env python3
"""Locate the Sven Co-op client ClientPortalManager::EnableClipPlane.

The clip-plane accumulator gates each portal surface behind up to six clip
planes and reports "Error: Too many clip planes on portal! Maximum: 6 (Too
many surfaces on brush?)" when the per-portal budget is exhausted. The
diagnostic belongs to the clip-plane function only on the validated 10257
client: a direct literal owner on Windows and a single GOTOFF displacement
site on Linux via the SvEngine PIC fallback. Its sole caller is RenderPortals,
matching MetaHookSv's EnableClipPlane role.
"""

from ida_preprocessor_scripts._sven_client_pic_common import (
    preprocess_string_owner_skill_with_pic_fallback,
)

TARGET_FUNCTION_NAMES = ["ClientPortalManager_EnableClipPlane"]
LITERAL = "Error: Too many clip planes on portal! Maximum: 6 (Too many surfaces on brush?)\n"


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
    return await preprocess_string_owner_skill_with_pic_fallback(
        session,
        expected_outputs=expected_outputs,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_name=TARGET_FUNCTION_NAMES[0],
        literal=LITERAL,
        debug=debug,
    )
