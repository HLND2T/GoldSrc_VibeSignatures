#!/usr/bin/env python3
"""Recover the GL extension string pointer from the existing GL_Init artifact.

Identify the global storing glGetString(GL_EXTENSIONS / 0x1F03)'s return
value and used by extension reporting/checks. Do not select the vendor,
renderer or version string, a qgl function pointer, or the string pointee.
All configured engine families share this role, including legacy BLOB/CoF
and Sven Linux PIC. Existing owner discovery is the only predecessor.
"""

from ida_analyze_util import preprocess_common_skill

TARGET_GLOBAL_NAMES = ["gl_extensions"]
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
        "reference_yaml_paths": ["references/{gamever}/engine/GL_Init.{platform}.yaml"],
        "expected_result_sections": ["found_gv"],
        "dependency_policy": {"GL_Init.{platform}.yaml": "required"},
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
