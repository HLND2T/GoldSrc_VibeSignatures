#!/usr/bin/env python3
"""Recover SvEngine's map reset from its verified resource-registration call.

SvEngine removed the window02_1 texture literal used by the other families.
The source role is the renderer reset after resource/model registration, not
the Hunk_Check call which follows it.
"""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = ["R_NewMap"]
LLM_DECOMPILE = [
    {
        "symbol_name": "R_NewMap",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": ["references/{gamever}/engine/CL_RegisterResources.{platform}.yaml"],
        "expected_result_sections": ["found_call"],
        "dependency_policy": {"CL_RegisterResources.{platform}.yaml": "required"},
    },
]
GENERATE_YAML_DESIRED_FIELDS = [
    ("R_NewMap", ["func_name", "func_va", "func_rva", "func_size", "func_sig"]),
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
        llm_decompile_specs=LLM_DECOMPILE,
        llm_config=llm_config,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )
