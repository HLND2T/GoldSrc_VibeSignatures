#!/usr/bin/env python3
"""Recover CASDocumentation::RegisterGlobalFunction from char isalnum registration.

FULLMATCH:bool isalnum(char character) locates a separate registration helper on
Windows and RegisterSCScriptVarious on Linux. The string overload in Windows 5.16
shares the documentation but not this declaration. Distinct predecessor artifacts
and references preserve the compiler's function boundary, without assuming a
cross-platform caller identity. Match the registration call, not the function
pointer in asSFuncPtr. Resolve ELF PLT entries to the method body.
"""

from ida_analyze_util import preprocess_common_skill
from cas_documentation_artifacts import publish_documentation_identities
from llm_spec import select_llm_specs

TARGET_FUNCTION_NAMES = ["CASDocumentation_RegisterGlobalFunction"]

LLM_DECOMPILE = {
    "windows": [
        {
            "symbol_name": "CASDocumentation_RegisterGlobalFunction",
            "prompt_path": "prompt/call_llm_decompile.md",
            "reference_yaml_paths": ["references/{gamever}/server/RegisterSCScriptCharacterFunctions.{platform}.yaml"],
            "expected_result_sections": ["found_call"],
            "dependency_policy": {"RegisterSCScriptCharacterFunctions.{platform}.yaml": "required"},
        }
    ],
    "linux": [
        {
            "symbol_name": "CASDocumentation_RegisterGlobalFunction",
            "prompt_path": "prompt/call_llm_decompile.md",
            "reference_yaml_paths": ["references/{gamever}/server/RegisterSCScriptVarious.{platform}.yaml"],
            "expected_result_sections": ["found_call"],
            "dependency_policy": {"RegisterSCScriptVarious.{platform}.yaml": "required"},
        }
    ],
}
GENERATE_YAML_DESIRED_FIELDS = [
    (
        "CASDocumentation_RegisterGlobalFunction",
        [
            "func_name",
            "func_va",
            "func_rva",
            "func_size",
            "func_sig",
            "func_sig_resolve_jmp_thunk:true",
            "func_sig_allow_across_function_boundary:true",
        ],
    )
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
    specs = select_llm_specs(LLM_DECOMPILE, branch=platform)
    targets = TARGET_FUNCTION_NAMES
    success = await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=None,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_names=targets,
        llm_decompile_specs=specs,
        llm_config=llm_config,
        generate_yaml_desired_fields=[spec for spec in GENERATE_YAML_DESIRED_FIELDS if spec[0] in targets],
        debug=debug,
    )
    if success:
        publish_documentation_identities(expected_outputs, platform)
    return success
