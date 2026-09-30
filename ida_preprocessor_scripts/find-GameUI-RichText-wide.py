#!/usr/bin/env python3
"""Recover the Unicode insertion call after localization / ANSI conversion.

The current ANSI predecessor is already anchored through condump. Its callee
has no target-owned unique literal or validated <=4-pattern discovery anchor.
Use the annotated direct call, then independently validate its wide traversal,
layout invalidation and repaint. Never use old artifact signatures to discover.
"""

from ida_preprocessor_scripts._gameui_richtext_common import ANSI, WIDE, recover_callee


LLM_DECOMPILE = [
    {
        "symbol_name": "GameUI_RichText_InsertStringW",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": ["references/{gamever}/gameui/GameUI_RichText_InsertStringA.{platform}.yaml"],
        "expected_result_sections": ["found_call"],
        "dependency_policy": {"GameUI_RichText_InsertStringA.{platform}.yaml": "required"},
    }
]


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
        llm_config,
        debug,
        llm_decompile_specs=LLM_DECOMPILE,
    )
