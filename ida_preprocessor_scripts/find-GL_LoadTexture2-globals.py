#!/usr/bin/env python3
"""Recover GoldSrc's texture array, used count and world spawn generation.

Reuse the existing deterministic GL_LoadTexture2 producer, including the
Draw_MiptexTexture predecessor on HL25 Linux. The array traversal bound and
new-slot increment identify numgltextures; gltextures is the static array,
not a pointer slot. gHostSpawnCount supplies the texture's servercount.
MetaHook's allocated_textures is already covered as texture_extension_number.
SvEngine uses a vector and has a separate finder/reference family.
"""

from ida_analyze_util import preprocess_common_skill

GV_NAMES = ["gltextures", "numgltextures", "gHostSpawnCount"]
GV_FIELDS = [
    "gv_name",
    "gv_va",
    "gv_rva",
    "gv_sig",
    "gv_sig_va",
    "gv_inst_offset",
    "gv_inst_length",
    "gv_inst_disp",
    "gv_pic_addend?",
    "gv_address_offset?",
]
LLM_DECOMPILE = [
    {
        "symbol_name": name,
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": ["references/{gamever}/engine/GL_LoadTexture2.{platform}.yaml"],
        "expected_result_sections": ["found_gv"],
        "dependency_policy": {"GL_LoadTexture2.{platform}.yaml": "required"},
    }
    for name in GV_NAMES
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
    return await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=None,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        gv_names=GV_NAMES,
        llm_decompile_specs=LLM_DECOMPILE,
        llm_config=llm_config,
        generate_yaml_desired_fields=[(name, GV_FIELDS) for name in GV_NAMES],
        debug=debug,
    )
