#!/usr/bin/env python3
"""Recover the non-inlined temporary entity pool initializer.

CoF supplies the shared Windows out-of-line reference body. The canonical
hl-10210 body inlines this call and cannot document a found_call locator.
"""

from ida_analyze_util import preprocess_common_skill

LLM_DECOMPILE = [
    {
        "symbol_name": "CL_TempEntInit",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": ["references/cof-5936/engine/CL_InitTEnts.{platform}.yaml"],
        "expected_result_sections": ["found_call"],
        "dependency_policy": {"CL_InitTEnts.{platform}.yaml": "required"},
    }
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
        func_names=["CL_TempEntInit"],
        llm_decompile_specs=LLM_DECOMPILE,
        llm_config=llm_config,
        generate_yaml_desired_fields=[
            ("CL_TempEntInit", ["func_name", "func_va", "func_rva", "func_size", "func_sig"])
        ],
        debug=debug,
    )
