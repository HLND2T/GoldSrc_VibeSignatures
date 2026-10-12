#!/usr/bin/env python3
"""Recover the entity clipping call, preserving the current binary's wrapper.

Classic Windows calls the trace-returning SV_ClipMoveToEntity wrapper. The
configured Linux builds inline that wrapper and call the six-argument SingleClip
entry directly; SvEngine 10257 calls the seven-argument entry on both platforms.
The 10152 ABI boundary applies to SvEngine, never to HL25's build number.
"""

from ida_analyze_util import _output_for_symbol, preprocess_common_skill
from ida_preprocessor_scripts._sv_clipping_common import normalize_singleclip
from llm_spec import select_llm_specs

LLM_DECOMPILE = {
    "wrapper": [
        {
            "symbol_name": "SV_ClipMoveToEntity",
            "prompt_path": "prompt/call_llm_decompile.md",
            "reference_yaml_paths": ["references/{gamever}/engine/SV_ClipToLinks.{platform}.yaml"],
            "expected_result_sections": ["found_call"],
            "dependency_policy": {"SV_ClipToLinks.{platform}.yaml": "required"},
        },
    ],
    "six": [
        {
            "symbol_name": "SV_SingleClipMoveToEntity",
            "prompt_path": "prompt/call_llm_decompile.md",
            "reference_yaml_paths": ["references/{gamever}/engine/SV_ClipToLinks.{platform}.yaml"],
            "expected_result_sections": ["found_call"],
            "dependency_policy": {"SV_ClipToLinks.{platform}.yaml": "required"},
        },
    ],
    "seven": [
        {
            "symbol_name": "SV_SingleClipMoveToEntity_10152",
            "prompt_path": "prompt/call_llm_decompile.md",
            "reference_yaml_paths": ["references/{gamever}/engine/SV_ClipToLinks.{platform}.yaml"],
            "expected_result_sections": ["found_call"],
            "dependency_policy": {"SV_ClipToLinks.{platform}.yaml": "required"},
        },
    ],
}


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
    if _output_for_symbol(expected_outputs, "SV_ClipMoveToEntity"):
        branch, name = "wrapper", "SV_ClipMoveToEntity"
    elif _output_for_symbol(expected_outputs, "SV_SingleClipMoveToEntity_10152"):
        branch, name = "seven", "SV_SingleClipMoveToEntity_10152"
    else:
        branch, name = "six", "SV_SingleClipMoveToEntity"
    success = await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=None,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_names=[name],
        llm_decompile_specs=select_llm_specs(LLM_DECOMPILE, branch=branch),
        llm_config=llm_config,
        generate_yaml_desired_fields=[(name, ["func_name", "func_va", "func_rva", "func_size", "func_sig"])],
        debug=debug,
    )
    if success and branch != "wrapper":
        return await normalize_singleclip(
            session, expected_outputs, image_base, name, 7 if branch == "seven" else 6, debug
        )
    return success
