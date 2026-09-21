#!/usr/bin/env python3
"""Locate R_UploadEmptyTex through ``**empty**``, excluding inlined R_Init.

GL_LoadTexture("**empty**") lives in R_UploadEmptyTex. SvEngine R_Init inlines
both empty and missing uploads, and HL25 Windows inlines the empty upload into
R_Init; those bodies also own ``**missing**`` or the ``gl_dump`` command and
are excluded. The remaining owner is the standalone function. SvEngine then
recovers ``r_emptytexture`` as the unique post-prologue writable global.
"""

from ida_preprocessor_scripts._host_palette_common import preprocess_upload_empty


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
    return await preprocess_upload_empty(session, expected_outputs, new_binary_dir, platform, image_base, debug=debug)
