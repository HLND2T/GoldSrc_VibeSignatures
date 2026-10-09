#!/usr/bin/env python3
"""Recover enum/namespace methods from OpenFile flag registration.

The predecessor's own flag documentation selects the standalone registration;
exclude the Windows CVirtualFileSystem registration that inlines the same flags.
Map enum OpenFile, READ=1, and SetDefaultNamespace("OpenFile") semantically.
RegisterEnumValue uses its own diagnostic on Windows and ELF 5.16. Only ELF 5.15
needs the READ call, selected by the production output inventory. No fixed call
ordinal or cross-version address is used; ELF PLT resolves to the real body.
"""

from pathlib import Path

from ida_analyze_util import preprocess_common_skill
from cas_documentation_artifacts import publish_documentation_identities
from llm_spec import select_llm_specs

TARGET_FUNCTION_NAMES = [
    "CASDocumentation_RegisterEnum",
    "CASDocumentation_SetDefaultNamespace",
    "CASDocumentation_RegisterEnumValue",
]

LLM_DECOMPILE = [
    {
        "symbol_name": "CASDocumentation_RegisterEnum",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": ["references/{gamever}/server/RegisterSCScriptOpenFileFlag.{platform}.yaml"],
        "expected_result_sections": ["found_call"],
        "dependency_policy": {"RegisterSCScriptOpenFileFlag.{platform}.yaml": "required"},
    },
    {
        "symbol_name": "CASDocumentation_SetDefaultNamespace",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": ["references/{gamever}/server/RegisterSCScriptOpenFileFlag.{platform}.yaml"],
        "expected_result_sections": ["found_call"],
        "dependency_policy": {"RegisterSCScriptOpenFileFlag.{platform}.yaml": "required"},
    },
    {
        "symbol_name": "CASDocumentation_RegisterEnumValue",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": ["references/{gamever}/server/RegisterSCScriptOpenFileFlag.{platform}.yaml"],
        "expected_result_sections": ["found_call"],
        "dependency_policy": {"RegisterSCScriptOpenFileFlag.{platform}.yaml": "required"},
    },
]
GENERATE_YAML_DESIRED_FIELDS = [
    (
        "CASDocumentation_RegisterEnum",
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
        "CASDocumentation_SetDefaultNamespace",
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
        "CASDocumentation_RegisterEnumValue",
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
    output_names = {path.name for path in map(Path, expected_outputs)}
    targets = [name for name in TARGET_FUNCTION_NAMES if f"{name}.{platform}.yaml" in output_names]
    specs = select_llm_specs(LLM_DECOMPILE, symbols=targets)
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
