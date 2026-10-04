#!/usr/bin/env python3
"""Recover receive/filter calls from the independently located menu poller.

Select the NS_SERVER Boolean receive loop and its ban predicate by source role,
never by call ordinal. Linux inlines the filter, whose retained independent body
is produced separately by the confirmed current-storage xrefs. The poller's
dedicated/state guards are consumer limitations, not constraints on these calls.
"""

from ida_analyze_util import preprocess_common_skill
from ida_preprocessor_scripts._native_rcon_common import preserve_function_identities
from llm_spec import select_llm_specs

LLM_DECOMPILE = {
    "windows": [
        {
            "symbol_name": "NET_GetPacket",
            "prompt_path": "prompt/call_llm_decompile.md",
            "reference_yaml_paths": ["references/{gamever}/engine/SV_CheckForRcon.{platform}.yaml"],
            "expected_result_sections": ["found_call"],
            "dependency_policy": {"SV_CheckForRcon.{platform}.yaml": "required"},
        },
        {
            "symbol_name": "SV_FilterPacket",
            "prompt_path": "prompt/call_llm_decompile.md",
            "reference_yaml_paths": ["references/{gamever}/engine/SV_CheckForRcon.{platform}.yaml"],
            "expected_result_sections": ["found_call"],
            "dependency_policy": {"SV_CheckForRcon.{platform}.yaml": "required"},
        },
    ],
    "linux": [
        {
            "symbol_name": "NET_GetPacket",
            "prompt_path": "prompt/call_llm_decompile.md",
            "reference_yaml_paths": ["references/{gamever}/engine/SV_CheckForRcon.{platform}.yaml"],
            "expected_result_sections": ["found_call"],
            "dependency_policy": {"SV_CheckForRcon.{platform}.yaml": "required"},
        },
    ],
}
FIELDS = ["func_name", "func_va", "func_rva", "func_size", "func_sig"]


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
    specs = select_llm_specs(LLM_DECOMPILE, branch=platform)
    names = ["NET_GetPacket", "SV_FilterPacket"] if platform == "windows" else ["NET_GetPacket"]
    found = await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=None,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_names=names,
        llm_decompile_specs=specs,
        llm_config=llm_config,
        generate_yaml_desired_fields=[(name, FIELDS) for name in names],
        debug=debug,
    )
    return found and await preserve_function_identities(
        session, expected_outputs, new_binary_dir, platform, image_base, names
    )
