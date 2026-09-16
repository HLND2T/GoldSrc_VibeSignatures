#!/usr/bin/env python3
"""Recover R_RenderScene from the verified R_RenderView body."""

from ida_analyze_util import preprocess_common_skill


TARGET_FUNC_NAME = "R_RenderScene"
PREDECESSOR = "R_RenderView"
FUNC_FIELDS = ["func_name", "func_sig", "func_va", "func_rva", "func_size"]
LLM_DECOMPILE = [
    {
        "symbol_name": TARGET_FUNC_NAME,
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": [f"references/{{gamever}}/engine/{PREDECESSOR}.{{platform}}.yaml"],
        "expected_result_sections": ["found_call"],
        "dependency_policy": {f"{PREDECESSOR}.{{platform}}.yaml": "required"},
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
        func_names=[TARGET_FUNC_NAME],
        llm_decompile_specs=LLM_DECOMPILE,
        llm_config=llm_config,
        generate_yaml_desired_fields=[(TARGET_FUNC_NAME, FUNC_FIELDS)],
        debug=debug,
    )
