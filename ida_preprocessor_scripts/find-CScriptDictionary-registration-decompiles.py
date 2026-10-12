#!/usr/bin/env python3
"""Recover dictionary native methods from their actual registration pointers.

Select object dictionary, native asCALL_THISCALL=3, behaviour 5/6 for
AddRef/Release, and the exact ? overload for Set/Get. Never return generic
wrappers (convention 6), another container, or a pointer's GOT storage slot.
IsEmpty/GetSize are standalone tiny bodies, recovered without adjacency scans.
Their output-only signatures may include neighboring code to remain unique.

Linux additionally publishes ScriptDictionaryFactory_Generic from factory
behaviour 3 / dictionary@ f() / asCALL_GENERIC=6; its engine Create call is
a separate DAG stage. Windows inlines construction in that generic factory.
"""

from ida_analyze_util import preprocess_common_skill
from llm_spec import select_llm_specs
from script_dictionary_artifacts import publish_dictionary_identities

LLM_DECOMPILE = {
    "windows": [
        {
            "symbol_name": "CScriptDictionary_AddRef",
            "prompt_path": "prompt/call_llm_decompile.md",
            "reference_yaml_paths": ["references/{gamever}/server/RegisterScriptDictionary.{platform}.yaml"],
            "expected_result_sections": ["found_funcptr"],
            "dependency_policy": {"RegisterScriptDictionary.{platform}.yaml": "required"},
        },
        {
            "symbol_name": "CScriptDictionary_Release",
            "prompt_path": "prompt/call_llm_decompile.md",
            "reference_yaml_paths": ["references/{gamever}/server/RegisterScriptDictionary.{platform}.yaml"],
            "expected_result_sections": ["found_funcptr"],
            "dependency_policy": {"RegisterScriptDictionary.{platform}.yaml": "required"},
        },
        {
            "symbol_name": "CScriptDictionary_Set",
            "prompt_path": "prompt/call_llm_decompile.md",
            "reference_yaml_paths": ["references/{gamever}/server/RegisterScriptDictionary.{platform}.yaml"],
            "expected_result_sections": ["found_funcptr"],
            "dependency_policy": {"RegisterScriptDictionary.{platform}.yaml": "required"},
        },
        {
            "symbol_name": "CScriptDictionary_Get",
            "prompt_path": "prompt/call_llm_decompile.md",
            "reference_yaml_paths": ["references/{gamever}/server/RegisterScriptDictionary.{platform}.yaml"],
            "expected_result_sections": ["found_funcptr"],
            "dependency_policy": {"RegisterScriptDictionary.{platform}.yaml": "required"},
        },
        {
            "symbol_name": "CScriptDictionary_Exists",
            "prompt_path": "prompt/call_llm_decompile.md",
            "reference_yaml_paths": ["references/{gamever}/server/RegisterScriptDictionary.{platform}.yaml"],
            "expected_result_sections": ["found_funcptr"],
            "dependency_policy": {"RegisterScriptDictionary.{platform}.yaml": "required"},
        },
        {
            "symbol_name": "CScriptDictionary_IsEmpty",
            "prompt_path": "prompt/call_llm_decompile.md",
            "reference_yaml_paths": ["references/{gamever}/server/RegisterScriptDictionary.{platform}.yaml"],
            "expected_result_sections": ["found_funcptr"],
            "dependency_policy": {"RegisterScriptDictionary.{platform}.yaml": "required"},
        },
        {
            "symbol_name": "CScriptDictionary_GetSize",
            "prompt_path": "prompt/call_llm_decompile.md",
            "reference_yaml_paths": ["references/{gamever}/server/RegisterScriptDictionary.{platform}.yaml"],
            "expected_result_sections": ["found_funcptr"],
            "dependency_policy": {"RegisterScriptDictionary.{platform}.yaml": "required"},
        },
        {
            "symbol_name": "CScriptDictionary_Delete",
            "prompt_path": "prompt/call_llm_decompile.md",
            "reference_yaml_paths": ["references/{gamever}/server/RegisterScriptDictionary.{platform}.yaml"],
            "expected_result_sections": ["found_funcptr"],
            "dependency_policy": {"RegisterScriptDictionary.{platform}.yaml": "required"},
        },
        {
            "symbol_name": "CScriptDictionary_DeleteAll",
            "prompt_path": "prompt/call_llm_decompile.md",
            "reference_yaml_paths": ["references/{gamever}/server/RegisterScriptDictionary.{platform}.yaml"],
            "expected_result_sections": ["found_funcptr"],
            "dependency_policy": {"RegisterScriptDictionary.{platform}.yaml": "required"},
        },
    ],
    "linux": [
        {
            "symbol_name": "CScriptDictionary_AddRef",
            "prompt_path": "prompt/call_llm_decompile.md",
            "reference_yaml_paths": ["references/{gamever}/server/RegisterScriptDictionary_Native.{platform}.yaml"],
            "expected_result_sections": ["found_funcptr"],
            "dependency_policy": {"RegisterScriptDictionary_Native.{platform}.yaml": "required"},
        },
        {
            "symbol_name": "CScriptDictionary_Release",
            "prompt_path": "prompt/call_llm_decompile.md",
            "reference_yaml_paths": ["references/{gamever}/server/RegisterScriptDictionary_Native.{platform}.yaml"],
            "expected_result_sections": ["found_funcptr"],
            "dependency_policy": {"RegisterScriptDictionary_Native.{platform}.yaml": "required"},
        },
        {
            "symbol_name": "CScriptDictionary_Set",
            "prompt_path": "prompt/call_llm_decompile.md",
            "reference_yaml_paths": ["references/{gamever}/server/RegisterScriptDictionary_Native.{platform}.yaml"],
            "expected_result_sections": ["found_funcptr"],
            "dependency_policy": {"RegisterScriptDictionary_Native.{platform}.yaml": "required"},
        },
        {
            "symbol_name": "CScriptDictionary_Get",
            "prompt_path": "prompt/call_llm_decompile.md",
            "reference_yaml_paths": ["references/{gamever}/server/RegisterScriptDictionary_Native.{platform}.yaml"],
            "expected_result_sections": ["found_funcptr"],
            "dependency_policy": {"RegisterScriptDictionary_Native.{platform}.yaml": "required"},
        },
        {
            "symbol_name": "CScriptDictionary_Exists",
            "prompt_path": "prompt/call_llm_decompile.md",
            "reference_yaml_paths": ["references/{gamever}/server/RegisterScriptDictionary_Native.{platform}.yaml"],
            "expected_result_sections": ["found_funcptr"],
            "dependency_policy": {"RegisterScriptDictionary_Native.{platform}.yaml": "required"},
        },
        {
            "symbol_name": "CScriptDictionary_IsEmpty",
            "prompt_path": "prompt/call_llm_decompile.md",
            "reference_yaml_paths": ["references/{gamever}/server/RegisterScriptDictionary_Native.{platform}.yaml"],
            "expected_result_sections": ["found_funcptr"],
            "dependency_policy": {"RegisterScriptDictionary_Native.{platform}.yaml": "required"},
        },
        {
            "symbol_name": "CScriptDictionary_GetSize",
            "prompt_path": "prompt/call_llm_decompile.md",
            "reference_yaml_paths": ["references/{gamever}/server/RegisterScriptDictionary_Native.{platform}.yaml"],
            "expected_result_sections": ["found_funcptr"],
            "dependency_policy": {"RegisterScriptDictionary_Native.{platform}.yaml": "required"},
        },
        {
            "symbol_name": "CScriptDictionary_Delete",
            "prompt_path": "prompt/call_llm_decompile.md",
            "reference_yaml_paths": ["references/{gamever}/server/RegisterScriptDictionary_Native.{platform}.yaml"],
            "expected_result_sections": ["found_funcptr"],
            "dependency_policy": {"RegisterScriptDictionary_Native.{platform}.yaml": "required"},
        },
        {
            "symbol_name": "CScriptDictionary_DeleteAll",
            "prompt_path": "prompt/call_llm_decompile.md",
            "reference_yaml_paths": ["references/{gamever}/server/RegisterScriptDictionary_Native.{platform}.yaml"],
            "expected_result_sections": ["found_funcptr"],
            "dependency_policy": {"RegisterScriptDictionary_Native.{platform}.yaml": "required"},
        },
        {
            "symbol_name": "ScriptDictionaryFactory_Generic",
            "prompt_path": "prompt/call_llm_decompile.md",
            "reference_yaml_paths": ["references/{gamever}/server/RegisterScriptDictionary_Native.{platform}.yaml"],
            "expected_result_sections": ["found_funcptr"],
            "dependency_policy": {"RegisterScriptDictionary_Native.{platform}.yaml": "required"},
        },
    ],
}

GENERATE_YAML_DESIRED_FIELDS = [
    (
        name,
        ["func_name", "func_va", "func_rva", "func_size", "func_sig", "func_sig_allow_across_function_boundary:true"],
    )
    for name in [
        "CScriptDictionary_AddRef",
        "CScriptDictionary_Release",
        "CScriptDictionary_Set",
        "CScriptDictionary_Get",
        "CScriptDictionary_Exists",
        "CScriptDictionary_IsEmpty",
        "CScriptDictionary_GetSize",
        "CScriptDictionary_Delete",
        "CScriptDictionary_DeleteAll",
        "ScriptDictionaryFactory_Generic",
    ]
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
    targets = [
        field[0]
        for field in GENERATE_YAML_DESIRED_FIELDS
        if platform == "linux" or field[0] != "ScriptDictionaryFactory_Generic"
    ]
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
        generate_yaml_desired_fields=[field for field in GENERATE_YAML_DESIRED_FIELDS if field[0] in targets],
        debug=debug,
    )
    return success and await publish_dictionary_identities(session, expected_outputs, platform, image_base)
