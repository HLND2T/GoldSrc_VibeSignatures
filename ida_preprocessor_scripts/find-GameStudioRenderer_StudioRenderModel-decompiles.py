#!/usr/bin/env python3
"""Recover renderer virtuals from the verified GameStudioRenderer_StudioRenderModel body."""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = ["GameStudioRenderer_StudioRenderFinal"]
LLM_DECOMPILE = [
    {
        "symbol_name": name,
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": ["references/{gamever}/client/GameStudioRenderer_StudioRenderModel.{platform}.yaml"],
        "expected_result_sections": ["found_vcall", "found_funcptr"],
        "dependency_policy": {"GameStudioRenderer_StudioRenderModel.{platform}.yaml": "required"},
    }
    for name in TARGET_FUNCTION_NAMES
]
VFUNC_FIELDS = [
    "func_name",
    "func_va",
    "func_rva",
    "func_size",
    "vtable_name",
    "vfunc_index",
    "vfunc_offset",
    "vfunc_sig",
]
GENERATE_YAML_DESIRED_FIELDS = [(name, VFUNC_FIELDS) for name in TARGET_FUNCTION_NAMES]


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
        func_names=TARGET_FUNCTION_NAMES,
        func_vtable_relations=[(name, "GameStudioRenderer") for name in TARGET_FUNCTION_NAMES],
        llm_decompile_specs=LLM_DECOMPILE,
        llm_config=llm_config,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )
