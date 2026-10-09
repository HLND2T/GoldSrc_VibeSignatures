#!/usr/bin/env python3
"""Recover CASBaseCallable::Call(int, ...) from platform-specific callers.

Windows Reflection GetReturnValue invokes a newly constructed assignment
callable; Linux ClientCommand Visit invokes its stored callback after checking
admin rights. Both pass this and a fixed int followed by variadic arguments on
the stack. Do not select Call(int, char*) or a logging variadic function.
ELF PLT entries are resolved to the method body. References preserve the actual
Windows inline conversion and Linux deque/command context independently.
"""

from as_callable_artifacts import publish_callable_identities
from ida_analyze_util import preprocess_common_skill
from llm_spec import select_llm_specs

LLM_DECOMPILE = {
    "windows": [
        {
            "symbol_name": "CASBaseCallable_Call",
            "prompt_path": "prompt/call_llm_decompile.md",
            "reference_yaml_paths": ["references/{gamever}/server/CASReflection_GetReturnValue.{platform}.yaml"],
            "expected_result_sections": ["found_call"],
            "dependency_policy": {"CASReflection_GetReturnValue.{platform}.yaml": "required"},
        }
    ],
    "linux": [
        {
            "symbol_name": "CASBaseCallable_Call",
            "prompt_path": "prompt/call_llm_decompile.md",
            "reference_yaml_paths": [
                "references/{gamever}/server/CASConCommandSystem_VisitClientCommand.{platform}.yaml"
            ],
            "expected_result_sections": ["found_call"],
            "dependency_policy": {"CASConCommandSystem_VisitClientCommand.{platform}.yaml": "required"},
        }
    ],
}
GENERATE_YAML_DESIRED_FIELDS = [
    (
        "CASBaseCallable_Call",
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
        func_names=["CASBaseCallable_Call"],
        llm_decompile_specs=select_llm_specs(LLM_DECOMPILE, branch=platform),
        llm_config=llm_config,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )
    if success:
        publish_callable_identities(expected_outputs, platform)
    return success
