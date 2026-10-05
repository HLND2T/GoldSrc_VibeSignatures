#!/usr/bin/env python3
"""Recover an inlined callback or follow the legacy API setup tail call."""

from ida_analyze_util import _output_for_symbol, preprocess_common_skill
from llm_spec import select_llm_specs

LLM_DECOMPILE = {
    "noinline": [
        {
            "symbol_name": "Sys_SetupLegacyAPIs",
            "prompt_path": "prompt/call_llm_decompile.md",
            "reference_yaml_paths": ["references/hl-3248/engine/Sys_InitLauncherInterface.{platform}.yaml"],
            "expected_result_sections": ["found_call"],
            "dependency_policy": {"Sys_InitLauncherInterface.{platform}.yaml": "required"},
        },
    ],
    "inline": [
        {
            "symbol_name": "Launcher_ConsolePrintf",
            "prompt_path": "prompt/call_llm_decompile.md",
            "reference_yaml_paths": ["references/hl-6153/engine/Sys_InitLauncherInterface.{platform}.yaml"],
            "expected_result_sections": ["found_gv"],
            "dependency_policy": {"Sys_InitLauncherInterface.{platform}.yaml": "required"},
        },
    ],
}
GENERATE_YAML_DESIRED_FIELDS = [
    (
        "Sys_SetupLegacyAPIs",
        ["func_name", "func_sig", "func_va", "func_rva", "func_size", "func_sig_allow_across_function_boundary:true"],
    ),
    (
        "Launcher_ConsolePrintf",
        [
            "gv_name",
            "gv_va",
            "gv_rva",
            "gv_sig",
            "gv_sig_va",
            "gv_inst_offset",
            "gv_inst_length",
            "gv_inst_disp",
            "gv_sig_allow_across_function_boundary:true",
        ],
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
    _ = skill_name, old_yaml_map
    inline = _output_for_symbol(expected_outputs, "Launcher_ConsolePrintf") is not None
    target_name = "Launcher_ConsolePrintf" if inline else "Sys_SetupLegacyAPIs"
    return await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=None,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_names=None if inline else ["Sys_SetupLegacyAPIs"],
        gv_names=["Launcher_ConsolePrintf"] if inline else None,
        llm_decompile_specs=select_llm_specs(LLM_DECOMPILE, branch="inline" if inline else "noinline"),
        llm_config=llm_config,
        generate_yaml_desired_fields=[entry for entry in GENERATE_YAML_DESIRED_FIELDS if entry[0] == target_name],
        debug=debug,
    )
