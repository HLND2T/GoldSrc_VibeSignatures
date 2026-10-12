#!/usr/bin/env python3
"""Recover the entity displacement call from SV_PushRotate.

SV_PushEntity returns trace_t by value (56 bytes in the tested engines), not a
trace_t pointer API. Its x86 machine call therefore includes a hidden return
buffer in addition to edict_t* and the three-float displacement vector.
"""

from ida_analyze_util import preprocess_common_skill

LLM_DECOMPILE = [
    {
        "symbol_name": "SV_PushEntity",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": ["references/{gamever}/engine/SV_PushRotate.{platform}.yaml"],
        "expected_result_sections": ["found_call"],
        "dependency_policy": {"SV_PushRotate.{platform}.yaml": "required"},
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
    return await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=None,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_names=["SV_PushEntity"],
        llm_decompile_specs=LLM_DECOMPILE,
        llm_config=llm_config,
        generate_yaml_desired_fields=[("SV_PushEntity", ["func_name", "func_va", "func_rva", "func_size", "func_sig"])],
        debug=debug,
    )
