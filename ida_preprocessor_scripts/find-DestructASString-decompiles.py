#!/usr/bin/env python3
"""Recover the native destructor from the registered destruction adapter.

Windows loads ECX=this then tail-jumps; Linux forwards the stack this argument
with a call (5.15 via PLT/GOT). Accept the actual call/jump instruction and resolve
the thunk. ClearMemory, which also resets fields, is not the destructor: the
reference plugin's 5.16 ELF signature incorrectly selects that sibling.
"""

from cstring_builder_artifacts import publish_identities
from ida_analyze_util import preprocess_common_skill

LLM_DECOMPILE = [
    {
        "symbol_name": "CString_dtor",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": ["references/{gamever}/server/DestructASString.{platform}.yaml"],
        "expected_result_sections": ["found_call"],
        "dependency_policy": {"DestructASString.{platform}.yaml": "required"},
    },
]
GENERATE_YAML_DESIRED_FIELDS = [
    (
        "CString_dtor",
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
        func_names=["CString_dtor"],
        llm_decompile_specs=LLM_DECOMPILE,
        llm_config=llm_config,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )
    return success and await publish_identities(session, expected_outputs, platform, image_base)
