#!/usr/bin/env python3
"""Recover the world entity base and model from the verified map-reset body.

R_NewMap clears the complete r_worldentity object. R_RenderView's access to its
model member alone would encode a field address instead of the entity base.
"""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = []
TARGET_GLOBAL_NAMES = ["r_worldentity", "cl_worldmodel"]
LLM_DECOMPILE = [
    {
        "symbol_name": name,
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": [
            "references/{gamever}/engine/R_NewMap.{platform}.yaml",
        ],
        "expected_result_sections": ["found_call" if name in TARGET_FUNCTION_NAMES else "found_gv"],
        "dependency_policy": {"R_NewMap.{platform}.yaml": "required"},
    }
    for name in TARGET_FUNCTION_NAMES + TARGET_GLOBAL_NAMES
]
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
]
GENERATE_YAML_DESIRED_FIELDS = [
    *((name, FUNC_FIELDS) for name in TARGET_FUNCTION_NAMES),
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
        func_names=TARGET_FUNCTION_NAMES,
        gv_names=TARGET_GLOBAL_NAMES,
        llm_decompile_specs=LLM_DECOMPILE,
        llm_config=llm_config,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )
