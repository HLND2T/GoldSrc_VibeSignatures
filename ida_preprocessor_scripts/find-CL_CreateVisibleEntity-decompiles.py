#!/usr/bin/env python3
"""Recover the visible-entity list/count from the non-beam insertion branch."""

from ida_analyze_util import preprocess_common_skill

TARGETS = ["cl_numvisedicts", "cl_visedicts"]
LLM_DECOMPILE = [
    {
        "symbol_name": name,
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": ["references/{gamever}/engine/CL_CreateVisibleEntity.{platform}.yaml"],
        "expected_result_sections": ["found_gv"],
        "dependency_policy": {"CL_CreateVisibleEntity.{platform}.yaml": "required"},
    }
    for name in TARGETS
]
GV_FIELDS = ["gv_name", "gv_va", "gv_rva", "gv_sig", "gv_sig_va", "gv_inst_offset", "gv_inst_length", "gv_inst_disp"]


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
        gv_names=TARGETS,
        llm_decompile_specs=LLM_DECOMPILE,
        llm_config=llm_config,
        generate_yaml_desired_fields=[(name, GV_FIELDS) for name in TARGETS],
        debug=debug,
    )
