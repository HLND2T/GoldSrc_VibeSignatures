#!/usr/bin/env python3
"""Recover world-renderer symbols from the verified world draw body."""

from ida_analyze_util import preprocess_common_skill


TARGET_FUNC_NAMES = ["R_RecursiveWorldNode"]
TARGET_GLOBAL_NAMES = ["modelorg"]
PREDECESSOR = "R_DrawWorld"
FUNC_FIELDS = ["func_name", "func_sig", "func_va", "func_rva", "func_size"]
GV_FIELDS = [
    "gv_name",
    "gv_va",
    "gv_rva",
    "gv_sig",
    "gv_sig_va",
    "gv_inst_offset",
    "gv_inst_length",
    "gv_inst_disp",
    "gv_sig_allow_across_function_boundary:true",
]
LLM_DECOMPILE = [
    {
        "symbol_name": name,
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": [f"references/{{gamever}}/engine/{PREDECESSOR}.{{platform}}.yaml"],
        "expected_result_sections": ["found_call" if name in TARGET_FUNC_NAMES else "found_gv"],
        "dependency_policy": {f"{PREDECESSOR}.{{platform}}.yaml": "required"},
    }
    for name in TARGET_FUNC_NAMES + TARGET_GLOBAL_NAMES
]
GENERATE_YAML_DESIRED_FIELDS = [
    *((name, FUNC_FIELDS) for name in TARGET_FUNC_NAMES),
    *((name, GV_FIELDS) for name in TARGET_GLOBAL_NAMES),
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
        func_names=TARGET_FUNC_NAMES,
        gv_names=TARGET_GLOBAL_NAMES,
        llm_decompile_specs=LLM_DECOMPILE,
        llm_config=llm_config,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )
