#!/usr/bin/env python3
"""Recover the out-of-line InsertChar called by the Unicode insertion loop.

Only registered on Windows revisions whose current loop has that direct call.
HL25 Windows and Linux inline it on the active console path. The hl-8684
reference preserves the older non-inlined source body, unlike hl-10210.
"""

from ida_preprocessor_scripts._gameui_richtext_common import CHAR, WIDE, recover_callee


async def preprocess_skill(
    session,
    skill_name,
    expected_outputs,
    old_yaml_map,
    new_binary_dir,
    platform,
    image_base,
    llm_config=None,
    debug=False,
):
    if platform != "windows":
        return False
    return await recover_callee(
        session,
        expected_outputs,
        new_binary_dir,
        platform,
        image_base,
        WIDE,
        CHAR,
        f"references/hl-8684/gameui/{WIDE}.{platform}.yaml",
        llm_config,
        debug,
    )
