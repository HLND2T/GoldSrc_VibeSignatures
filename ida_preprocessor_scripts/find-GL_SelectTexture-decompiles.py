#!/usr/bin/env python3
"""Recover multitexture capability and the cached texture unit from GL_SelectTexture.

The capability flag gates the GL unit-selection call. oldtarget is compared
with the requested unit, indexes the previous binding cache, and is replaced
by that unit. currenttexture is already covered by find-GL_Bind-currenttexture.
Use the current predecessor body, including PIC/GOT operands on SvEngine Linux;
prior artifact signatures are never discovery inputs."""

from ida_analyze_util import preprocess_common_skill

TARGET_NAMES = ["gl_mtexable", "oldtarget"]
PREDECESSOR = "GL_SelectTexture"
LLM_DECOMPILE = [
    {
        "symbol_name": name,
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": [f"references/{{gamever}}/engine/{PREDECESSOR}.{{platform}}.yaml"],
        "expected_result_sections": ["found_gv"],
        "dependency_policy": {f"{PREDECESSOR}.{{platform}}.yaml": "required"},
    }
    for name in TARGET_NAMES
]
DESIRED_FIELDS = [
    "gv_name",
    "gv_va",
    "gv_rva",
    "gv_sig",
    "gv_sig_va",
    "gv_inst_offset",
    "gv_inst_length",
    "gv_inst_disp",
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
        gv_names=TARGET_NAMES,
        llm_decompile_specs=LLM_DECOMPILE,
        llm_config=llm_config,
        generate_yaml_desired_fields=[(name, DESIRED_FIELDS) for name in TARGET_NAMES],
        debug=debug,
    )
