#!/usr/bin/env python3
"""Recover GL_Bind from the verified lightmap rebuild body.

GL_BuildLightmaps rebinds lightmap textures through GL_Bind
(engine/gl_rsurf.c), and the lightmap pass is its densest distinct callee: the
call site resolves uniquely from the annotated reference body on every
validated branch. Output is the GL_Bind function entry; the multiple call
sites inside the body cross-validate the same function and are not emitted as
callsite artifacts.
"""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNC_NAME = "GL_Bind"
REFERENCE = "GL_BuildLightmaps"
LLM_DECOMPILE = [
    {
        "symbol_name": TARGET_FUNC_NAME,
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": [
            f"references/{{gamever}}/engine/{REFERENCE}.{{platform}}.yaml",
        ],
        "expected_result_sections": ["found_call"],
        "dependency_policy": {f"{REFERENCE}.{{platform}}.yaml": "required"},
    },
]
FUNC_FIELDS = ["func_name", "func_sig", "func_va", "func_rva", "func_size"]


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
        func_names=[TARGET_FUNC_NAME],
        llm_decompile_specs=LLM_DECOMPILE,
        llm_config=llm_config,
        generate_yaml_desired_fields=[(TARGET_FUNC_NAME, FUNC_FIELDS)],
        debug=debug,
    )
