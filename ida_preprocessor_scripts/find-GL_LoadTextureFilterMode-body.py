#!/usr/bin/env python3
"""Recover SvEngine's register-ABI texture loader from its public wrapper.

The existing GL_LoadTexture2 artifact names the nine-argument
GL_LoadTextureFilterMode wrapper on Linux. Its enabled path tail-jumps to
the .part.14 body (the retained 8948 ELF name); do not confuse either entry
with an eight-argument decal specialization. The current wrapper's branch
operand, not a reference address or call ordinal, determines the body.
"""

from ida_analyze_util import preprocess_common_skill

TARGET = "GL_LoadTextureFilterMode_part_14"
LLM_DECOMPILE = [
    {
        "symbol_name": TARGET,
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": ["references/{gamever}/engine/GL_LoadTexture2.{platform}.yaml"],
        "expected_result_sections": ["found_call"],
        "dependency_policy": {"GL_LoadTexture2.{platform}.yaml": "required"},
        "instruction_rules": [
            {"regex": r"jmp\s+.+", "text": "Select the enabled path's direct tail jump to the texture-loading body."}
        ],
    }
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
    if platform != "linux":
        return False
    return await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=None,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_names=[TARGET],
        llm_decompile_specs=LLM_DECOMPILE,
        llm_config=llm_config,
        generate_yaml_desired_fields=[(TARGET, ["func_name", "func_va", "func_rva", "func_sig", "func_size"])],
        debug=debug,
    )
