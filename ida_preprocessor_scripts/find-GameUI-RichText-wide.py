#!/usr/bin/env python3
"""Recover the Unicode insertion call after localization / ANSI conversion.

The current ANSI predecessor is already anchored through condump. Its callee
has no target-owned unique literal or validated <=4-pattern discovery anchor.
Use the annotated direct call, then independently validate its wide traversal,
layout invalidation and repaint. Never use old artifact signatures to discover.
"""

from ida_preprocessor_scripts._gameui_richtext_common import ANSI, WIDE, recover_callee


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
    return await recover_callee(
        session,
        expected_outputs,
        new_binary_dir,
        platform,
        image_base,
        ANSI,
        WIDE,
        f"references/{{gamever}}/gameui/{ANSI}.{platform}.yaml",
        llm_config,
        debug,
    )
