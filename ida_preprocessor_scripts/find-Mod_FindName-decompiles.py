#!/usr/bin/env python3
"""Recover the model registry array and count from its verified name lookup."""

from ida_analyze_util import preprocess_common_skill

TARGET_GLOBAL_NAMES = ["mod_known", "mod_numknown"]
LLM_DECOMPILE = [
    {
        "symbol_name": "mod_known",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": ["references/{gamever}/engine/Mod_FindName.{platform}.yaml"],
        "expected_result_sections": ["found_gv"],
        "dependency_policy": {"Mod_FindName.{platform}.yaml": "required"},
    },
    {
        "symbol_name": "mod_numknown",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": ["references/{gamever}/engine/Mod_FindName.{platform}.yaml"],
        "expected_result_sections": ["found_gv"],
        "dependency_policy": {"Mod_FindName.{platform}.yaml": "required"},
    },
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
        gv_names=TARGET_GLOBAL_NAMES,
        llm_decompile_specs=LLM_DECOMPILE,
        llm_config=llm_config,
        generate_yaml_desired_fields=[(name, GV_FIELDS) for name in TARGET_GLOBAL_NAMES],
        debug=debug,
    )
