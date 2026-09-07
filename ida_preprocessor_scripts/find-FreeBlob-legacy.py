#!/usr/bin/env python3
"""Locate FreeBlob from the standalone ClientDLL_Shutdown body.

HL25 inlines ClientDLL_Shutdown into ClientDLL_Init; those binaries keep using
find-FreeBlob. Older GoldSrc (and hl-8684 Windows) keep a standalone
ClientDLL_Shutdown whose secure-client path calls FreeBlob. The predecessor
reference is generated from hl-6153.
"""

from ida_analyze_util import preprocess_common_skill


TARGET_FUNCTION_NAMES = ["FreeBlob"]

LLM_DECOMPILE = [
    {
        "symbol_name": "FreeBlob",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": [
            "references/hl-6153/engine/ClientDLL_Shutdown.{platform}.yaml",
        ],
        "expected_result_sections": ["found_call"],
        "dependency_policy": {
            "ClientDLL_Shutdown.{platform}.yaml": "required",
        },
    },
]

GENERATE_YAML_DESIRED_FIELDS = [
    ("FreeBlob", ["func_name", "func_sig", "func_va", "func_rva", "func_size"]),
]
GENERATE_YAML_DESIRED_FIELDS_ACROSS_BOUNDARY = [
    (
        "FreeBlob",
        ["func_name", "func_sig", "func_va", "func_rva", "func_size", "func_sig_allow_across_function_boundary:true"],
    ),
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
    _ = skill_name
    common_arguments = {
        "session": session,
        "expected_outputs": expected_outputs,
        "old_yaml_map": None,
        "new_binary_dir": new_binary_dir,
        "platform": platform,
        "image_base": image_base,
        "func_names": TARGET_FUNCTION_NAMES,
        "llm_decompile_specs": LLM_DECOMPILE,
        "llm_config": llm_config,
        "debug": debug,
    }
    if await preprocess_common_skill(
        **common_arguments,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
    ):
        return True
    return await preprocess_common_skill(
        **common_arguments,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS_ACROSS_BOUNDARY,
    )
