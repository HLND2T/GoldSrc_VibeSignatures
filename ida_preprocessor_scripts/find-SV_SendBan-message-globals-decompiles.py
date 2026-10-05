#!/usr/bin/env python3
"""Select the incoming address and whole native message object; verify current send field offsets."""

from ida_preprocessor_scripts._native_rcon_globals_common import preprocess_globals

LLM_DECOMPILE = [
    {
        "symbol_name": "net_from",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": ["references/{gamever}/engine/SV_SendBan.{platform}.yaml"],
        "expected_result_sections": ["found_gv"],
        "dependency_policy": {"SV_SendBan.{platform}.yaml": "required"},
        "instruction_rules": [
            {
                "regex": r"^\s*(?:mov\w*|lea|push|cmp)\s+.*$",
                "text": "Select an instruction carrying the whole net_from object base. Reject a field address, interior array element, pointer slot, or adjacent object.",
            }
        ],
    },
    {
        "symbol_name": "net_message",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": ["references/{gamever}/engine/SV_SendBan.{platform}.yaml"],
        "expected_result_sections": ["found_gv"],
        "dependency_policy": {"SV_SendBan.{platform}.yaml": "required"},
        "instruction_rules": [
            {
                "regex": r"^\s*(?:mov\w*|lea|push|cmp)\s+.*$",
                "text": "Select an instruction carrying the whole net_message object base. Reject a field address, interior array element, pointer slot, or adjacent object.",
            }
        ],
    },
    {
        "symbol_name": "sizebuf_t_data_offset",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": ["references/{gamever}/engine/SV_SendBan.{platform}.yaml"],
        "expected_result_sections": ["found_scalar"],
        "dependency_policy": {"SV_SendBan.{platform}.yaml": "required"},
    },
    {
        "symbol_name": "sizebuf_t_cursize_offset",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": ["references/{gamever}/engine/SV_SendBan.{platform}.yaml"],
        "expected_result_sections": ["found_scalar"],
        "dependency_policy": {"SV_SendBan.{platform}.yaml": "required"},
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
        "message",
        ["net_from", "net_message"],
        ["SV_SendBan", "NET_SendPacket", "NET_GetPacket"],
        llm_config,
        debug,
        llm_decompile_specs=LLM_DECOMPILE,
    )
