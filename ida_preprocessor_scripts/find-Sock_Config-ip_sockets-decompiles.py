#!/usr/bin/env python3
"""Select the NS_CLIENT starting slot of SvEngine's IP socket array, not the NS_SERVER slot."""

from ida_preprocessor_scripts._native_rcon_globals_common import preprocess_globals

LLM_DECOMPILE = [
    {
        "symbol_name": "ip_sockets",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": ["references/{gamever}/engine/Sock_Config.{platform}.yaml"],
        "expected_result_sections": ["found_gv"],
        "dependency_policy": {"Sock_Config.{platform}.yaml": "required"},
        "instruction_rules": [
            {
                "regex": r"^\s*(?:mov\w*|lea|push|cmp)\s+.*$",
                "text": "Select an instruction carrying the whole ip_sockets object base. Reject a field address, interior array element, pointer slot, or adjacent object.",
            }
        ],
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
        "sven_socket",
        ["ip_sockets"],
        ["Sock_Config", "NET_Config"],
        llm_config,
        debug,
        llm_decompile_specs=LLM_DECOMPILE,
    )
