#!/usr/bin/env python3
"""Recover the non-inlined launcher initializer called by Sys_InitGame."""

from ida_analyze_util import preprocess_common_skill

LLM_DECOMPILE = [
    {
        "symbol_name": "Sys_InitLauncherInterface",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": ["references/hl-3248/engine/Sys_InitGame.{platform}.yaml"],
        "expected_result_sections": ["found_call"],
        "dependency_policy": {"Sys_InitGame.{platform}.yaml": "required"},
    },
]
GENERATE_YAML_DESIRED_FIELDS = [
    (
        "Sys_InitLauncherInterface",
        ["func_name", "func_sig", "func_va", "func_rva", "func_size", "func_sig_allow_across_function_boundary:true"],
    ),
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
        func_names=["Sys_InitLauncherInterface"],
        llm_decompile_specs=LLM_DECOMPILE,
        llm_config=llm_config,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )
