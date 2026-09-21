#!/usr/bin/env python3
"""Recover host_basepal from the Hunk_AllocName(2048) palette store.

engine/host.c assigns ``host_basepal = Hunk_AllocName(2048, "palette.lmp")``.
GoldSrc keeps that store in Host_Init; SvEngine moved it to
Host_LoadBasePalette. The locator takes the unique remaining owner of the
SvEngine palette diagnostic (excluding Host_Init's heap banner) or Host_Init's
palette Sys_Error literal, then the unique store of the 0x800 Hunk_AllocName
return value.
"""

from ida_preprocessor_scripts._host_palette_common import preprocess_host_basepal


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
    _ = skill_name, old_yaml_map, new_binary_dir
    return await preprocess_host_basepal(session, expected_outputs, new_binary_dir, platform, image_base, debug=debug)
