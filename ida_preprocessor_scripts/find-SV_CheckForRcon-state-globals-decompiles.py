#!/usr/bin/env python3
"""Select the whole server and exit-state globals, cross-checking the native clear and initialization paths."""

from ida_preprocessor_scripts._native_rcon_globals_common import preprocess_globals

LLM_DECOMPILE = [
    {
        "symbol_name": "sv",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": ["references/{gamever}/engine/SV_CheckForRcon.{platform}.yaml"],
        "expected_result_sections": ["found_gv"],
        "dependency_policy": {"SV_CheckForRcon.{platform}.yaml": "required"},
        "instruction_rules": [
            {
                "regex": r"^\s*(?:mov\w*|lea|push|cmp)\s+.*$",
                "text": "Select an instruction carrying the whole sv object base. Reject a field address, interior array element, pointer slot, or adjacent object.",
            }
        ],
    },
    {
        "symbol_name": "giActive",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": ["references/{gamever}/engine/SV_CheckForRcon.{platform}.yaml"],
        "expected_result_sections": ["found_gv"],
        "dependency_policy": {"SV_CheckForRcon.{platform}.yaml": "required"},
    },
    {
        "symbol_name": "sv_active_offset",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": ["references/{gamever}/engine/SV_CheckForRcon.{platform}.yaml"],
        "expected_result_sections": ["found_scalar"],
        "dependency_policy": {"SV_CheckForRcon.{platform}.yaml": "required"},
    },
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
    return await preprocess_globals(
        session,
        expected_outputs,
        new_binary_dir,
        platform,
        image_base,
        "poller",
        ["sv", "giActive"],
        ["SV_CheckForRcon", "Host_ClearMemory", "Host_Init"],
        llm_config,
        debug,
        llm_decompile_specs=LLM_DECOMPILE,
    )
