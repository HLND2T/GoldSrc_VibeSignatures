#!/usr/bin/env python3
"""Recover CScriptArray::Release from SetItemMappings' array ownership changes.

Identify release of the previous array or release of the rejected incoming
array, not GetArrayObjectType or a logging call. Sven 5.15 ELF32 calls an
EBX-relative .plt.got entry; resolve its verified relocated GOT pointer to the
actual Release body. Array/Grid body collisions must not be discovery anchors.
An extended output signature includes the destructor/free path and, if needed,
the following GC accessors; it is output validation only.
"""

from as_callable_artifacts import publish_callable_identities
from ida_analyze_util import preprocess_common_skill

LLM_DECOMPILE = [
    {
        "symbol_name": "CScriptArray_Release",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": ["references/{gamever}/server/CClassicMode_SetItemMappings.{platform}.yaml"],
        "expected_result_sections": ["found_call"],
        "dependency_policy": {"CClassicMode_SetItemMappings.{platform}.yaml": "required"},
    }
]
GENERATE_YAML_DESIRED_FIELDS = [
    (
        "CScriptArray_Release",
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
    success = await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=None,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_names=["CScriptArray_Release"],
        llm_decompile_specs=LLM_DECOMPILE,
        llm_config=llm_config,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )
    if success:
        publish_callable_identities(expected_outputs, platform)
    return success
