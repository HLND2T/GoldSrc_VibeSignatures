#!/usr/bin/env python3
"""Recover CString adapters from actual string registration descriptors.

Select object string / exact opAssign(const string&) / asCALL_THISCALL=3 for
CString::operator=. Select behaviour asBEHAVE_DESTRUCT=2 / void Destructstring()
/ asCALL_CDECL_OBJLAST=4 for DestructASString. The latter is a cdecl adapter,
not the native destructor. Both targets share one registration reference.
ELF GOT storage is not a callable entry; validate its executable pointee.
"""

from cstring_builder_artifacts import publish_identities
from ida_analyze_util import preprocess_common_skill

LLM_DECOMPILE = [
    {
        "symbol_name": "CString_opAssign",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": ["references/{gamever}/server/RegisterSCScriptASString.{platform}.yaml"],
        "expected_result_sections": ["found_funcptr"],
        "dependency_policy": {"RegisterSCScriptASString.{platform}.yaml": "required"},
    },
    {
        "symbol_name": "DestructASString",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": ["references/{gamever}/server/RegisterSCScriptASString.{platform}.yaml"],
        "expected_result_sections": ["found_funcptr"],
        "dependency_policy": {"RegisterSCScriptASString.{platform}.yaml": "required"},
    },
]
GENERATE_YAML_DESIRED_FIELDS = [
    (
        name,
        ["func_name", "func_va", "func_rva", "func_size", "func_sig", "func_sig_allow_across_function_boundary:true"],
    )
    for name in ["CString_opAssign", "DestructASString"]
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
        func_names=[field[0] for field in GENERATE_YAML_DESIRED_FIELDS],
        llm_decompile_specs=LLM_DECOMPILE,
        llm_config=llm_config,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )
    return success and await publish_identities(session, expected_outputs, platform, image_base)
