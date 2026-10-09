#!/usr/bin/env python3
"""Recover CASDocumentation behaviour/property registration from color24.

The predecessor owns "Color24 structure". Its default constructor registration
(void color24(), behaviour 0) locates RegisterObjectBehaviour; its int8 r property
at offset zero locates RegisterObjectProperty on Linux. Windows uses the latter
method's own diagnostic instead. The property offset is only a verified call
argument, not a separately published struct member. Output signatures never
participate in discovery; ELF PLT entries are resolved to actual method bodies.
"""

from ida_analyze_util import preprocess_common_skill
from cas_documentation_artifacts import publish_documentation_identities
from llm_spec import select_llm_specs

TARGET_FUNCTION_NAMES = {
    "windows": ["CASDocumentation_RegisterObjectBehaviour"],
    "linux": ["CASDocumentation_RegisterObjectBehaviour", "CASDocumentation_RegisterObjectProperty"],
}

LLM_DECOMPILE = {
    "windows": [
        {
            "symbol_name": "CASDocumentation_RegisterObjectBehaviour",
            "prompt_path": "prompt/call_llm_decompile.md",
            "reference_yaml_paths": ["references/{gamever}/server/RegisterSCScriptColor24.{platform}.yaml"],
            "expected_result_sections": ["found_call"],
            "dependency_policy": {"RegisterSCScriptColor24.{platform}.yaml": "required"},
        }
    ],
    "linux": [
        {
            "symbol_name": "CASDocumentation_RegisterObjectBehaviour",
            "prompt_path": "prompt/call_llm_decompile.md",
            "reference_yaml_paths": ["references/{gamever}/server/RegisterSCScriptColor24.{platform}.yaml"],
            "expected_result_sections": ["found_call"],
            "dependency_policy": {"RegisterSCScriptColor24.{platform}.yaml": "required"},
        },
        {
            "symbol_name": "CASDocumentation_RegisterObjectProperty",
            "prompt_path": "prompt/call_llm_decompile.md",
            "reference_yaml_paths": ["references/{gamever}/server/RegisterSCScriptColor24.{platform}.yaml"],
            "expected_result_sections": ["found_call"],
            "dependency_policy": {"RegisterSCScriptColor24.{platform}.yaml": "required"},
        },
    ],
}
GENERATE_YAML_DESIRED_FIELDS = [
    (
        "CASDocumentation_RegisterObjectBehaviour",
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
    (
        "CASDocumentation_RegisterObjectProperty",
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
    specs = select_llm_specs(LLM_DECOMPILE, branch=platform)
    targets = TARGET_FUNCTION_NAMES[platform]
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
