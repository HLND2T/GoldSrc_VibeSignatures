#!/usr/bin/env python3
"""Recover gSpriteMipMap from the verified sprite-frame loader.

Mod_LoadSpriteFrame reads gSpriteMipMap to choose the sprite texture class and
passes the same value to GL_LoadTexture. The annotated source-like predecessor
pins that read while allowing the Windows absolute and Linux PIC/GOT encodings
to be resolved by the shared global-variable artifact writer.
"""

from ida_analyze_util import preprocess_common_skill


TARGET_GLOBAL_NAMES = ["gSpriteMipMap"]
REFERENCE = "Mod_LoadSpriteFrame"
LLM_DECOMPILE = [
    {
        "symbol_name": "gSpriteMipMap",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": [
            f"references/{{gamever}}/engine/{REFERENCE}.{{platform}}.yaml",
        ],
        "expected_result_sections": ["found_gv"],
        "dependency_policy": {f"{REFERENCE}.{{platform}}.yaml": "required"},
    },
]
GV_FIELDS = [
    "gv_name",
    "gv_va",
    "gv_rva",
    "gv_sig",
    "gv_sig_va",
    "gv_inst_offset",
    "gv_inst_length",
    "gv_inst_disp",
]
GENERATE_YAML_DESIRED_FIELDS = [("gSpriteMipMap", GV_FIELDS)]


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
        gv_names=TARGET_GLOBAL_NAMES,
        llm_decompile_specs=LLM_DECOMPILE,
        llm_config=llm_config,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )
