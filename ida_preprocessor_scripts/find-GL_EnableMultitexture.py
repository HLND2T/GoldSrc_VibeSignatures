#!/usr/bin/env python3
"""Recover the non-inlined multitexture enable helper from R_DrawSequentialPoly.

Registered only for GoldSrc/HL25/CoF Windows. Identify the direct callee that
checks capability, selects texture unit 1, enables GL_TEXTURE_2D and sets the
multitexture state. Linux and SvEngine Windows recover that state from the
inlined drawing body instead."""

from ida_analyze_util import preprocess_common_skill

TARGET_NAMES = ["GL_EnableMultitexture"]
PREDECESSOR = "R_DrawSequentialPoly"
LLM_DECOMPILE = [
    {
        "symbol_name": name,
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": [f"references/{{gamever}}/engine/{PREDECESSOR}.{{platform}}.yaml"],
        "expected_result_sections": ["found_call"],
        "dependency_policy": {f"{PREDECESSOR}.{{platform}}.yaml": "required"},
    }
    for name in TARGET_NAMES
]
DESIRED_FIELDS = ["func_name", "func_sig", "func_va", "func_rva", "func_size"]


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
        func_names=TARGET_NAMES,
        llm_decompile_specs=LLM_DECOMPILE,
        llm_config=llm_config,
        generate_yaml_desired_fields=[(name, DESIRED_FIELDS) for name in TARGET_NAMES],
        debug=debug,
    )
