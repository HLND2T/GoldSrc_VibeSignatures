#!/usr/bin/env python3
"""Recover the engine detail-texture support flag from DT_LoadDetailMapFile.

DT_LoadDetailMapFile opens with ``if (!detTexSupported) { return; }``; the
selected operand is ``detTexSupported`` itself.  DT_Initialize cannot be the
predecessor on the BLOB builds because it is inlined into GL_MultiTexInit and
its flag store then lives in a jump-target block outside the recorded function.
"""

from ida_analyze_util import preprocess_common_skill

TARGET_GLOBAL_NAMES = ["detTexSupported"]
LLM_DECOMPILE = [
    {
        "symbol_name": name,
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": ["references/{gamever}/engine/DT_LoadDetailMapFile.{platform}.yaml"],
        "expected_result_sections": ["found_gv"],
        "dependency_policy": {"DT_LoadDetailMapFile.{platform}.yaml": "required"},
    }
    for name in TARGET_GLOBAL_NAMES
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
GENERATE_YAML_DESIRED_FIELDS = [(name, GV_FIELDS) for name in TARGET_GLOBAL_NAMES]


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
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )
