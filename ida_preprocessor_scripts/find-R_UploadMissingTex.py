#!/usr/bin/env python3
"""Locate SvEngine R_UploadMissingTex through ``**missing**``.

GL_LoadTexture("**missing**") lives in R_UploadMissingTex. Windows R_Init
inlines both missing and empty uploads, so ``**empty**`` is excluded and only
the standalone function remains. ``r_missingtexture`` is the unique
post-prologue writable global in that body.
"""

from ida_preprocessor_scripts._host_palette_common import preprocess_upload_missing


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
    return await preprocess_upload_missing(session, expected_outputs, new_binary_dir, platform, image_base, debug=debug)
