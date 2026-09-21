#!/usr/bin/env python3
"""Locate Host_Init through its family-specific diagnostic literal.

GoldSrc/HL25/CoF abort palette loading with
``Host_Init: Couldn't load gfx/palette.lmp`` inside Host_Init itself.
SvEngine replaced that path and prints ``Heap size: %4.1f MB\\n`` from the
same function. Each literal has exactly one owner on its family; the finder
tries them in that order.
"""

from ida_preprocessor_scripts._host_palette_common import preprocess_host_init


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
    return await preprocess_host_init(session, expected_outputs, new_binary_dir, platform, image_base, debug=debug)
