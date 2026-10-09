#!/usr/bin/env python3
"""Recover Linux GetTypeInfoByName from KeepIfPrevious's string-array validation.

The required predecessor is anchored by its own array-type diagnostic. Select
the call taking the manager and a temporary libstdc++ __cxx11 string("string"),
whose result is compared with the array element's type info before emitting that
diagnostic. The SDK engine query through vtable slot 0xdc is a different call.
Version-specific references preserve actual 5.15/5.16 argument materialization;
there is no call ordinal, fixed offset, byte-pattern or mangled-name discovery.
Resolve the 5.15 PLT at the selected instruction to the actual method body.
"""

from ida_analyze_util import preprocess_common_skill
from cas_directory_manager_artifacts import publish_directory_manager_identities

TARGET_FUNCTION_NAMES = ["CASBaseManager_GetTypeInfoByName"]
LLM_DECOMPILE = [
    {
        "symbol_name": "CASBaseManager_GetTypeInfoByName",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": ["references/{gamever}/server/CASPersistence_KeepIfPrevious.{platform}.yaml"],
        "expected_result_sections": ["found_call"],
        "dependency_policy": {"CASPersistence_KeepIfPrevious.{platform}.yaml": "required"},
    },
]
GENERATE_YAML_DESIRED_FIELDS = [
    (
        "CASBaseManager_GetTypeInfoByName",
        ["func_name", "func_va", "func_rva", "func_size", "func_sig", "func_sig_resolve_jmp_thunk:true"],
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
    if platform != "linux":
        return False
    success = await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=None,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_names=TARGET_FUNCTION_NAMES,
        llm_decompile_specs=LLM_DECOMPILE,
        llm_config=llm_config,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )
    if success:
        publish_directory_manager_identities(expected_outputs, platform)
    return success
