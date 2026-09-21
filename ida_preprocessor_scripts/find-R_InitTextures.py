#!/usr/bin/env python3
"""Locate R_InitTextures as the Host_Init callee before HPAK ``custom``.

Host_Init always constructs the fallback textures and then checks the custom
HPAK: ``R_InitTextures(); HPAK_CheckIntegrity("custom");``. The previous
direct call from the unique ``custom`` xref inside the revalidated Host_Init
body is R_InitTextures. GoldSrc/HL25/CoF then recover ``r_notexture_mip`` as
the unique writable global stored in that body (the Hunk_AllocName result).
"""

from ida_preprocessor_scripts._host_palette_common import preprocess_r_init_textures


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
    return await preprocess_r_init_textures(
        session, expected_outputs, new_binary_dir, platform, image_base, debug=debug
    )
