#!/usr/bin/env python3
"""Recover four CASDocumentation methods from custom-entity registration.

The predecessor owns the Think-function documentation literal. Map RegisterFuncDef
from void ThinkFunction(), RegisterObjectType from CCustomEntityFuncs,
RegisterObjectMethod from IsCustomEntity, and RegisterGlobalProperty from
CCustomEntityFuncs g_CustomEntityFuncs. The Windows callback-handler registration
is inlined here; Linux calls a separate helper. Those are not our call anchors.
References preserve each version's actual calls and ABI. Output signatures only
validate discovered entries; ELF PLT entries are resolved to method bodies.
"""

from ida_analyze_util import preprocess_common_skill
from cas_documentation_artifacts import publish_documentation_identities

TARGET_FUNCTION_NAMES = [
    "CASDocumentation_RegisterObjectType",
    "CASDocumentation_RegisterGlobalProperty",
    "CASDocumentation_RegisterObjectMethod",
    "CASDocumentation_RegisterFuncDef",
]

LLM_DECOMPILE = [
    {
        "symbol_name": "CASDocumentation_RegisterObjectType",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": [
            "references/{gamever}/server/RegisterSCScriptCustomEntityDependencies.{platform}.yaml"
        ],
        "expected_result_sections": ["found_call"],
        "dependency_policy": {"RegisterSCScriptCustomEntityDependencies.{platform}.yaml": "required"},
    },
    {
        "symbol_name": "CASDocumentation_RegisterGlobalProperty",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": [
            "references/{gamever}/server/RegisterSCScriptCustomEntityDependencies.{platform}.yaml"
        ],
        "expected_result_sections": ["found_call"],
        "dependency_policy": {"RegisterSCScriptCustomEntityDependencies.{platform}.yaml": "required"},
    },
    {
        "symbol_name": "CASDocumentation_RegisterObjectMethod",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": [
            "references/{gamever}/server/RegisterSCScriptCustomEntityDependencies.{platform}.yaml"
        ],
        "expected_result_sections": ["found_call"],
        "dependency_policy": {"RegisterSCScriptCustomEntityDependencies.{platform}.yaml": "required"},
    },
    {
        "symbol_name": "CASDocumentation_RegisterFuncDef",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": [
            "references/{gamever}/server/RegisterSCScriptCustomEntityDependencies.{platform}.yaml"
        ],
        "expected_result_sections": ["found_call"],
        "dependency_policy": {"RegisterSCScriptCustomEntityDependencies.{platform}.yaml": "required"},
    },
]
GENERATE_YAML_DESIRED_FIELDS = [
    (
        "CASDocumentation_RegisterObjectType",
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
        "CASDocumentation_RegisterGlobalProperty",
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
        "CASDocumentation_RegisterObjectMethod",
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
        "CASDocumentation_RegisterFuncDef",
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
    specs = LLM_DECOMPILE
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
