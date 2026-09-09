#!/usr/bin/env python3
"""Locate studioapi_SetupPlayerModel CALL/JMP sites that target
R_StudioChangePlayerModel.

SCModelDownloader redirects those branches to its own wrapper instead of
hooking R_StudioChangePlayerModel globally. Each qualifying instruction is
a separate patch artifact:

    studioapi_SetupPlayerModel_to_R_StudioChangePlayerModel_callsite_0
    studioapi_SetupPlayerModel_to_R_StudioChangePlayerModel_callsite_1
    ...

Numbering is the studioapi_SetupPlayerModel-body instruction address order,
starting at 0. MSVC merges the two source call sites into one on
hl-4554..hl-10210 and cof-5936 (single artifact); the WON-era hl builds and
SvEngine keep both. Linux builds inline the callee, so this finder is
Windows-only by design.

patch_va / patch_rva are the unique patch_sig match start. patch_sig_disp
is the byte displacement from that match to the CALL/JMP; this helper
always starts the signature at the branch, so patch_sig_disp is 0.
patch_bytes is omitted: the consumer computes the redirect at runtime.
"""

from ida_preprocessor_scripts._func_to_func_callsites_common import preprocess_func_to_func_callsites

PATCH_NAME_PREFIX = "studioapi_SetupPlayerModel_to_R_StudioChangePlayerModel_callsite_"
OWNER_FUNC_NAME = "studioapi_SetupPlayerModel"
CALLEE_FUNC_NAME = "R_StudioChangePlayerModel"


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
