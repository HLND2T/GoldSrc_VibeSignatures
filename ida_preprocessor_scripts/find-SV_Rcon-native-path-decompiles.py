#!/usr/bin/env python3
"""Recover synchronous Cmd_ExecuteString inside the native Rcon redirect scope.

Its requested two-argument entry preserves each engine's privilege-check path.
Do not replace it with Cbuf execution or a compiler's internal command core.
"""

from ida_analyze_util import preprocess_common_skill
from ida_preprocessor_scripts._native_rcon_common import preserve_function_identities

LLM_DECOMPILE = [
    {
        "symbol_name": "Cmd_ExecuteString",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": ["references/{gamever}/engine/SV_Rcon.{platform}.yaml"],
        "expected_result_sections": ["found_call"],
        "dependency_policy": {"SV_Rcon.{platform}.yaml": "required"},
    },
]
FIELDS = ["func_name", "func_va", "func_rva", "func_size", "func_sig", "func_sig_allow_across_function_boundary?"]


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
    names = ["Cmd_ExecuteString"]
    found = await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=None,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_names=names,
        llm_decompile_specs=LLM_DECOMPILE,
        llm_config=llm_config,
        generate_yaml_desired_fields=[("Cmd_ExecuteString", FIELDS)],
        debug=debug,
    )
    return found and await preserve_function_identities(
        session, expected_outputs, new_binary_dir, platform, image_base, names
    )
