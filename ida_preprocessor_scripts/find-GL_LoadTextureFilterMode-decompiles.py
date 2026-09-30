#!/usr/bin/env python3
"""Recover SvEngine texture globals and the allocation predecessor.

gltextures is the CUtlVector<gltexture_t> object (_ZL10gltextures in 8948
ELF), not an independent pointer variable. peakgltextures is the separate
high-water mark (_ZL14peakgltextures). gHostSpawnCount supplies servercount.
Windows inlines InsertBefore and calls the engine's static CRT realloc;
Linux calls InsertBefore, which owns the later realloc@plt invocation.
"""

from ida_analyze_util import preprocess_common_skill

GV_NAMES = ["gltextures", "peakgltextures", "gHostSpawnCount"]
WINDOWS_MEMBER_GVS = ["gltextures.m_Size", "gltextures.m_Memory.m_nAllocationCount"]
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


LLM_DECOMPILE = {
    "windows": [
        {
            "symbol_name": "gltextures",
            "prompt_path": "prompt/call_llm_decompile.md",
            "reference_yaml_paths": ["references/{gamever}/engine/GL_LoadTexture2.{platform}.yaml"],
            "expected_result_sections": ["found_gv"],
            "dependency_policy": {"GL_LoadTexture2.{platform}.yaml": "required"},
        },
        {
            "symbol_name": "peakgltextures",
            "prompt_path": "prompt/call_llm_decompile.md",
            "reference_yaml_paths": ["references/{gamever}/engine/GL_LoadTexture2.{platform}.yaml"],
            "expected_result_sections": ["found_gv"],
            "dependency_policy": {"GL_LoadTexture2.{platform}.yaml": "required"},
        },
        {
            "symbol_name": "gHostSpawnCount",
            "prompt_path": "prompt/call_llm_decompile.md",
            "reference_yaml_paths": ["references/{gamever}/engine/GL_LoadTexture2.{platform}.yaml"],
            "expected_result_sections": ["found_gv"],
            "dependency_policy": {"GL_LoadTexture2.{platform}.yaml": "required"},
        },
        {
            "symbol_name": "gltextures.m_Size",
            "prompt_path": "prompt/call_llm_decompile.md",
            "reference_yaml_paths": ["references/{gamever}/engine/GL_LoadTexture2.{platform}.yaml"],
            "expected_result_sections": ["found_gv"],
            "dependency_policy": {"GL_LoadTexture2.{platform}.yaml": "required"},
        },
        {
            "symbol_name": "gltextures.m_Memory.m_nAllocationCount",
            "prompt_path": "prompt/call_llm_decompile.md",
            "reference_yaml_paths": ["references/{gamever}/engine/GL_LoadTexture2.{platform}.yaml"],
            "expected_result_sections": ["found_gv"],
            "dependency_policy": {"GL_LoadTexture2.{platform}.yaml": "required"},
        },
        {
            "symbol_name": "realloc",
            "prompt_path": "prompt/call_llm_decompile.md",
            "reference_yaml_paths": ["references/{gamever}/engine/GL_LoadTexture2.{platform}.yaml"],
            "expected_result_sections": ["found_call"],
            "dependency_policy": {"GL_LoadTexture2.{platform}.yaml": "required"},
        },
    ],
    "linux": [
        {
            "symbol_name": "gltextures",
            "prompt_path": "prompt/call_llm_decompile.md",
            "reference_yaml_paths": ["references/{gamever}/engine/GL_LoadTextureFilterMode_part_14.{platform}.yaml"],
            "expected_result_sections": ["found_gv"],
            "dependency_policy": {"GL_LoadTextureFilterMode_part_14.{platform}.yaml": "required"},
            "instruction_rules": [
                {
                    "regex": "(?i)lea\\s+e(?:ax|bx|cx|dx|si|di|bp),\\s*.+",
                    "text": "Select the LEA that materializes the gltextures CUtlVector "
                    "object base passed as this to "
                    "CUtlVector_gltexture_t_InsertBefore. Do not select MOV loads of "
                    "m_pMemory, interior count/capacity fields, or other references "
                    "to the same storage.",
                }
            ],
        },
        {
            "symbol_name": "peakgltextures",
            "prompt_path": "prompt/call_llm_decompile.md",
            "reference_yaml_paths": ["references/{gamever}/engine/GL_LoadTextureFilterMode_part_14.{platform}.yaml"],
            "expected_result_sections": ["found_gv"],
            "dependency_policy": {"GL_LoadTextureFilterMode_part_14.{platform}.yaml": "required"},
        },
        {
            "symbol_name": "gHostSpawnCount",
            "prompt_path": "prompt/call_llm_decompile.md",
            "reference_yaml_paths": ["references/{gamever}/engine/GL_LoadTextureFilterMode_part_14.{platform}.yaml"],
            "expected_result_sections": ["found_gv"],
            "dependency_policy": {"GL_LoadTextureFilterMode_part_14.{platform}.yaml": "required"},
        },
        {
            "symbol_name": "CUtlVector_gltexture_t_InsertBefore",
            "prompt_path": "prompt/call_llm_decompile.md",
            "reference_yaml_paths": ["references/{gamever}/engine/GL_LoadTextureFilterMode_part_14.{platform}.yaml"],
            "expected_result_sections": ["found_call"],
            "dependency_policy": {"GL_LoadTextureFilterMode_part_14.{platform}.yaml": "required"},
        },
    ],
}


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
    function = "realloc" if platform == "windows" else "CUtlVector_gltexture_t_InsertBefore"
    gv_names = GV_NAMES + (WINDOWS_MEMBER_GVS if platform == "windows" else [])
    specs = LLM_DECOMPILE[platform]
    return await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=None,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_names=[function],
        gv_names=gv_names,
        llm_decompile_specs=specs,
        llm_config=llm_config,
        generate_yaml_desired_fields=[
            *[(name, GV_FIELDS) for name in gv_names],
            (
                function,
                [
                    "func_name",
                    "func_va",
                    "func_rva",
                    "func_sig",
                    "func_size",
                    "func_sig_allow_across_function_boundary:true",
                ],
            ),
        ],
        debug=debug,
    )
