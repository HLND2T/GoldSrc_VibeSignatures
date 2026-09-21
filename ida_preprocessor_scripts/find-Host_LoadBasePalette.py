#!/usr/bin/env python3
"""Locate SvEngine Host_LoadBasePalette through its palette-load diagnostic.

SvEngine extracted the GoldSrc Host_Init palette load into
Host_LoadBasePalette. The function owns
``Could not load base palette from "%s".\\n``. On Windows Host_Init inlines
the same body, so the Heap-size Host_Init literal is excluded and only the
standalone Host_LoadBasePalette remains.
"""

from ida_preprocessor_scripts._host_palette_common import preprocess_host_load_base_palette


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
    return await preprocess_host_load_base_palette(
        session, expected_outputs, new_binary_dir, platform, image_base, debug=debug
    )
