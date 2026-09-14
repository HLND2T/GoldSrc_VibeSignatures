#!/usr/bin/env python3
"""Recover R_LoadSkyBox_SvEngine from the verified SvEngine skybox command.

The SvEngine skybox command forwards Cmd_Argv(1) to the outer skybox loader,
which gates on the loading state, clears the old sky textures, calls the
internal loader and falls back to desert. The SvEngine body genuinely
differs from the shared hl family, so it keeps its own svencoop-10257
reference; the annotated reference pins the loader call site. Used on the
svencoop-10257 Linux branch where the desert literal has two function
owners.
"""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNC_NAME = "R_LoadSkyBox_SvEngine"
REFERENCE = "SkyboxCommand"
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
