#!/usr/bin/env python3
"""Recover Assign from the registered CString copy-assignment method.

The method reads the source CString buffer/length and calls Assign on this.
Exclude three-argument substring Assign overloads. Resolve the ELF 5.15 PLT
before publishing the native body. No signature or fixed call offset discovers it.
"""

from cstring_builder_artifacts import publish_identities
from ida_analyze_util import preprocess_common_skill

LLM_DECOMPILE = [
    {
        "symbol_name": "CString_Assign",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": ["references/{gamever}/server/CString_opAssign.{platform}.yaml"],
        "expected_result_sections": ["found_call"],
        "dependency_policy": {"CString_opAssign.{platform}.yaml": "required"},
    },
]
GENERATE_YAML_DESIRED_FIELDS = [
    (
        "CString_Assign",
        [
            "func_name",
            "func_va",
            "func_rva",
            "func_size",
            "func_sig",
            "func_sig_resolve_jmp_thunk:true",
            "func_sig_allow_across_function_boundary:true",
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
    success = await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=None,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_names=["CString_Assign"],
        llm_decompile_specs=LLM_DECOMPILE,
        llm_config=llm_config,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )
    return success and await publish_identities(session, expected_outputs, platform, image_base)
