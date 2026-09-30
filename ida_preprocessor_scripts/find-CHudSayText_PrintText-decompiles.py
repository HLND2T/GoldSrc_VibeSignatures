#!/usr/bin/env python3
"""Recover GetClientColor from the default/server/player name-color calls.

Sven's PrintText body passes -1, zero, or the player index to the same color
selector. The reference labels those calls, without using their ordinal.
Resolve ELF PLT/jump thunks to the actual method body before writing output."""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = ["GetClientColor"]
LLM_DECOMPILE = [
    {
        "symbol_name": "GetClientColor",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": ["references/{gamever}/client/CHudSayText_PrintText.{platform}.yaml"],
        "expected_result_sections": ["found_call"],
        "dependency_policy": {"CHudSayText_PrintText.{platform}.yaml": "required"},
    }
]
FIELDS = ["func_name", "func_va", "func_rva", "func_size", "func_sig", "func_sig_resolve_jmp_thunk:true"]
GENERATE_YAML_DESIRED_FIELDS = [(name, FIELDS) for name in TARGET_FUNCTION_NAMES]


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
