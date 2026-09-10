#!/usr/bin/env python3
"""Recover V_RenderView between viewport refdef calculation and GL_Set2D."""

from ida_analyze_util import preprocess_common_skill

LLM_DECOMPILE = [
    {
        "symbol_name": "V_RenderView",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": ["references/{gamever}/engine/VGui_ViewportPaintBackground.{platform}.yaml"],
        "expected_result_sections": ["found_call"],
        "dependency_policy": {"VGui_ViewportPaintBackground.{platform}.yaml": "required"},
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
        func_names=["V_RenderView"],
        llm_decompile_specs=LLM_DECOMPILE,
        llm_config=llm_config,
        generate_yaml_desired_fields=[("V_RenderView", ["func_name", "func_va", "func_rva", "func_size", "func_sig"])],
        debug=debug,
    )
