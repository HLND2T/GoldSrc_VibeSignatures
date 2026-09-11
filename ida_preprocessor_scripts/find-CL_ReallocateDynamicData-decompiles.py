#!/usr/bin/env python3
"""Recover entity allocation globals and the complete client frame ring.

The frame-ring memset owns the array base, unlike render accesses that may
encode a playerstate member address within each frame.
"""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = []
TARGET_GLOBAL_NAMES = ["cl_max_edicts", "cl_entities", "cl_frames"]
LLM_DECOMPILE = [
    {
        "symbol_name": name,
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": [
            "references/{gamever}/engine/CL_ReallocateDynamicData.{platform}.yaml",
        ],
        "expected_result_sections": ["found_call" if name in TARGET_FUNCTION_NAMES else "found_gv"],
        "dependency_policy": {"CL_ReallocateDynamicData.{platform}.yaml": "required"},
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
