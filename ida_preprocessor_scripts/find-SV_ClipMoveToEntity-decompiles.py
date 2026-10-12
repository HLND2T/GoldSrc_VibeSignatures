#!/usr/bin/env python3
"""Recover the six-argument SingleClip entry inside the trace-returning wrapper."""

from ida_analyze_util import preprocess_common_skill
from ida_preprocessor_scripts._sv_clipping_common import normalize_singleclip

LLM_DECOMPILE = [
    {
        "symbol_name": "SV_SingleClipMoveToEntity",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": ["references/hl-8684/engine/SV_ClipMoveToEntity.{platform}.yaml"],
        "expected_result_sections": ["found_call"],
        "dependency_policy": {"SV_ClipMoveToEntity.{platform}.yaml": "required"},
    },
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
    _ = skill_name, old_yaml_map
    success = await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=None,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_names=["SV_SingleClipMoveToEntity"],
        llm_decompile_specs=LLM_DECOMPILE,
        llm_config=llm_config,
        generate_yaml_desired_fields=[
            ("SV_SingleClipMoveToEntity", ["func_name", "func_va", "func_rva", "func_size", "func_sig"])
        ],
        debug=debug,
    )
    return success and await normalize_singleclip(
        session, expected_outputs, image_base, "SV_SingleClipMoveToEntity", 6, debug
    )
