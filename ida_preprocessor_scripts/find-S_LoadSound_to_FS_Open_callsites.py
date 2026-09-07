#!/usr/bin/env python3
"""Locate S_LoadSound CALL/JMP sites that target FS_Open.

ResourceReplacer redirects those branches to S_LoadSound_FS_Open instead of
hooking FS_Open globally. Each qualifying instruction is a separate patch
artifact:

    S_LoadSound_to_FS_Open_callsite_0
    S_LoadSound_to_FS_Open_callsite_1
    ...

Numbering is the S_LoadSound-body instruction address order, starting at 0.

patch_va / patch_rva are the unique patch_sig match start. patch_sig_disp is the
byte displacement from that match to the CALL/JMP. This finder always starts the
signature at the branch, so patch_sig_disp is 0. patch_bytes is omitted: the
consumer computes the redirect at runtime.
"""

from ida_preprocessor_scripts._func_to_func_callsites_common import preprocess_func_to_func_callsites

PATCH_NAME_PREFIX = "S_LoadSound_to_FS_Open_callsite_"
OWNER_FUNC_NAME = "S_LoadSound"
CALLEE_FUNC_NAME = "FS_Open"


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
    _ = old_yaml_map
    return await preprocess_func_to_func_callsites(
        session,
        skill_name,
        expected_outputs,
        new_binary_dir,
        platform,
        image_base,
        patch_name_prefix=PATCH_NAME_PREFIX,
        owner_func_name=OWNER_FUNC_NAME,
        callee_func_name=CALLEE_FUNC_NAME,
        debug=debug,
    )
