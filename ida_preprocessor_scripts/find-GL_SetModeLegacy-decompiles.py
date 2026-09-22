#!/usr/bin/env python3
"""Recover the legacy vid_d3d cvar value from the existing GL_SetModeLegacy.

The fD3D branch sets vid_d3d.value to 1.0f before QGL_D3DInit. The target
is the writable float member, not the cvar_t base or the integer driver
flag. Its explicit member name follows scr_fov_value. Only legacy Windows
builds register this skill; hl-4554 provides the shared legacy reference.
"""

from ida_analyze_util import preprocess_common_skill

TARGET_GLOBAL_NAMES = ["vid_d3d_value"]
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
LLM_DECOMPILE = [
    {
        "symbol_name": name,
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": ["references/hl-4554/engine/GL_SetModeLegacy.{platform}.yaml"],
        "expected_result_sections": ["found_gv"],
        "dependency_policy": {"GL_SetModeLegacy.{platform}.yaml": "required"},
    }
    for name in TARGET_GLOBAL_NAMES
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
        gv_names=TARGET_GLOBAL_NAMES,
        llm_decompile_specs=LLM_DECOMPILE,
        llm_config=llm_config,
        generate_yaml_desired_fields=[(name, GV_FIELDS) for name in TARGET_GLOBAL_NAMES],
        debug=debug,
    )
