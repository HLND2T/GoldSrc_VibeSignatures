#!/usr/bin/env python3
"""Recover the shared four-frustum-plane box culler from StudioCheckBBox."""

from ida_analyze_util import preprocess_common_skill

LLM_DECOMPILE = [
    {
        "symbol_name": "R_CullBox",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": ["references/{gamever}/engine/R_StudioCheckBBox.{platform}.yaml"],
        "expected_result_sections": ["found_call"],
        "dependency_policy": {"R_StudioCheckBBox.{platform}.yaml": "required"},
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
    _ = skill_name, old_yaml_map
    return await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=None,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_names=["R_CullBox"],
        llm_decompile_specs=LLM_DECOMPILE,
        llm_config=llm_config,
        generate_yaml_desired_fields=[("R_CullBox", ["func_name", "func_va", "func_rva", "func_size", "func_sig"])],
        debug=debug,
    )
