#!/usr/bin/env python3
"""Recover filterMode from the verified SetFilterMode_I argument stores.

Identify each target by argument dataflow, never by global address ordering.
The Linux operand may identify an address through PIC/GOT; shared x86
validation must resolve the object, not publish the GOT slot as the global.
"""

from ida_analyze_util import preprocess_common_skill
from ida_preprocessor_scripts._engine_filter_globals_common import filter_global_specs

TARGET_GLOBAL_NAMES = ["filterMode"]
LLM_DECOMPILE = [
    {
        "symbol_name": name,
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": ["references/{gamever}/engine/SetFilterMode_I.{platform}.yaml"],
        "expected_result_sections": ["found_gv"],
        "dependency_policy": {"SetFilterMode_I.{platform}.yaml": "required"},
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
    "gv_sig_allow_across_function_boundary:true",
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
        llm_decompile_specs=filter_global_specs(LLM_DECOMPILE, platform),
        llm_config=llm_config,
        generate_yaml_desired_fields=[(name, GV_FIELDS) for name in TARGET_GLOBAL_NAMES],
        debug=debug,
    )
