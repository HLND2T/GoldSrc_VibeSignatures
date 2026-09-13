#!/usr/bin/env python3
"""Recover GL_LoadTexture2 from the verified wad-cached miptex draw entry.

Draw_MiptexTexture uploads a cached wad miptex through the full nine
argument GL_LoadTexture2 (engine/gl_draw.c). The same body also contains a
specialized upload entry that must not be mistaken for the canonical
wrapper; the annotated reference pins the nine-argument call site. Used on
the hl-10210 Linux branch where GL_LoadTexture2 has no single-owner string
anchor.
"""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNC_NAME = "GL_LoadTexture2"
REFERENCE = "Draw_MiptexTexture"
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
