#!/usr/bin/env python3
"""Recover command-buffer execution and network configuration from the initializer.

Host_InitializeGameDLL is independently anchored by its duplicate-init diagnostic.
Its buffer execution and maxclients > 1 network configuration calls have no useful
target-owned literals. Identify their source roles from the annotated current-body
reference, never by call ordinal. Cbuf_Execute remains the public multi-buffer
wrapper in engines that split its implementation.
"""

from ida_analyze_util import preprocess_common_skill
from ida_preprocessor_scripts._native_rcon_common import preserve_function_identities

NAMES = ["Cbuf_Execute", "NET_Config"]
LLM_DECOMPILE = [
    {
        "symbol_name": "Cbuf_Execute",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": ["references/{gamever}/engine/Host_InitializeGameDLL.{platform}.yaml"],
        "expected_result_sections": ["found_call"],
        "dependency_policy": {"Host_InitializeGameDLL.{platform}.yaml": "required"},
    },
    {
        "symbol_name": "NET_Config",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": ["references/{gamever}/engine/Host_InitializeGameDLL.{platform}.yaml"],
        "expected_result_sections": ["found_call"],
        "dependency_policy": {"Host_InitializeGameDLL.{platform}.yaml": "required"},
    },
]
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
    found = await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=None,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_names=NAMES,
        llm_decompile_specs=LLM_DECOMPILE,
        llm_config=llm_config,
        generate_yaml_desired_fields=[
            ("Cbuf_Execute", FIELDS),
            # SvEngine's short configuration wrapper needs surrounding bytes
            # for a unique output signature; these are never discovery anchors.
            ("NET_Config", FIELDS + ["func_sig_allow_across_function_boundary:true"]),
        ],
        debug=debug,
    )
    return found and await preserve_function_identities(
        session, expected_outputs, new_binary_dir, platform, image_base, NAMES
    )
