#!/usr/bin/env python3
"""Locate client-engine globals that share one LLM decompile reference."""

from ida_analyze_util import preprocess_common_skill


TARGET_GV_NAMES = ["g_ppEngfuncs", "g_ppExportFuncs", "g_phClientModule"]
LLM_REFERENCE_GROUPS = [
    {
        "symbol_names": ["g_ppEngfuncs", "g_ppExportFuncs"],
        "reference_yaml_paths": [
            "references/{gamever}/engine/ClientDLL_Init.{platform}.yaml",
        ],
        "dependency_policy": {
            "ClientDLL_Init.{platform}.yaml": "required",
        },
    },
    {
        "symbol_names": ["g_phClientModule"],
        "reference_yaml_paths": [
            "references/{gamever}/engine/ClientDLL_HudInit.{platform}.yaml",
        ],
        "dependency_policy": {
            "ClientDLL_HudInit.{platform}.yaml": "required",
        },
    },
]
LLM_DECOMPILE = [
    {
        "symbol_name": symbol_name,
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": group["reference_yaml_paths"],
        "expected_result_sections": ["found_gv"],
        "dependency_policy": group["dependency_policy"],
    }
    for group in LLM_REFERENCE_GROUPS
    for symbol_name in group["symbol_names"]
]
GV_FIELDS = [
    "gv_name",
    "gv_va",
    "gv_rva",
    "gv_sig",
    "gv_sig_va",
    "gv_inst_offset",
    "gv_inst_length",
    "gv_inst_disp",
    "gv_sig_allow_across_function_boundary?",
]
GENERATE_YAML_DESIRED_FIELDS = [(symbol_name, GV_FIELDS) for symbol_name in TARGET_GV_NAMES]


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
        gv_names=TARGET_GV_NAMES,
        llm_decompile_specs=LLM_DECOMPILE,
        llm_config=llm_config,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )
