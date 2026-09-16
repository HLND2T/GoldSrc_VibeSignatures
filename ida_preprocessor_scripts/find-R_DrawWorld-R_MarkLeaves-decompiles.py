#!/usr/bin/env python3
"""Recover the world draw and PVS-marking functions from R_RenderScene."""

from pathlib import Path

from ida_analyze_util import preprocess_common_skill


TARGET_FUNCTION_NAMES = ["R_DrawWorld", "R_MarkLeaves"]
PREDECESSOR = "R_RenderScene"
FUNC_FIELDS = ["func_name", "func_sig", "func_va", "func_rva", "func_size"]
LLM_DECOMPILE = [
    {
        "symbol_name": name,
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": [f"references/{{gamever}}/engine/{PREDECESSOR}.{{platform}}.yaml"],
        "expected_result_sections": ["found_call"],
        "dependency_policy": {f"{PREDECESSOR}.{{platform}}.yaml": "required"},
    }
    for name in TARGET_FUNCTION_NAMES
]


def _desired_fields(new_binary_dir, platform):
    gamever = Path(new_binary_dir).resolve().parent.name if new_binary_dir else ""
    draw_world_fields = list(FUNC_FIELDS)
    if gamever == "hl-10210" and platform == "linux":
        draw_world_fields.append("func_sig_allow_across_function_boundary:true")
    return [("R_DrawWorld", draw_world_fields), ("R_MarkLeaves", FUNC_FIELDS)]


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
        llm_decompile_specs=LLM_DECOMPILE,
        llm_config=llm_config,
        generate_yaml_desired_fields=_desired_fields(new_binary_dir, platform),
        debug=debug,
    )
