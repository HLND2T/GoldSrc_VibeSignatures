#!/usr/bin/env python3
"""Recover the transparent-object subsystem globals.

`transObjects` and `maxTransObjs` come from the two absolute writable stores in
the verified R_AllocTransObjects body; `numTransObjs` is the counter that
R_DrawTEntitiesOnList resets to zero. The MetaHookSv `maxTransObjs - 4`
derivation is deliberately not used: the three globals are laid out differently
on Windows, on GoldSrc Linux and on SvEngine Linux.
"""

from ida_preprocessor_scripts._renderer_private_globals_common import (
    preprocess_trans_object_globals,
)


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
    return await preprocess_trans_object_globals(
        session,
        expected_outputs,
        new_binary_dir,
        platform,
        image_base,
        debug=debug,
    )
