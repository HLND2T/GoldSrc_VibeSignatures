#!/usr/bin/env python3
"""Recover CASHook::Call(int, ...) from OnMapEnd's map-change hook invocation.

OnMapEnd is independently anchored by its own active-module diagnostic.
Its map-change hook is called before clearing manager/map state; 5.16 also
passes a temporary map-name CString. Separate version references preserve
this difference. Identify the semantic call, never a byte pattern, fixed
offset or call ordinal. Resolve the ELF 5.15 PLT to the actual method body,
and exclude the Call(CBasePlayer*, int, ...) overload by the reference role.
"""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = ["CASHook_Call"]
LLM_DECOMPILE = [
    {
        "symbol_name": "CASHook_Call",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": ["references/{gamever}/server/CASBaseManager_OnMapEnd.{platform}.yaml"],
        "expected_result_sections": ["found_call"],
        "dependency_policy": {"CASBaseManager_OnMapEnd.{platform}.yaml": "required"},
    },
]
GENERATE_YAML_DESIRED_FIELDS = [
    (
        "CASHook_Call",
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
    return await preprocess_common_skill(
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
