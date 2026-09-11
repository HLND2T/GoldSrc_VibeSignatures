#!/usr/bin/env python3
"""Recover renderer virtuals from the verified GameStudioRenderer_StudioDrawModel body."""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = [
    "GameStudioRenderer_StudioDrawPlayer",
    "GameStudioRenderer_StudioSaveBones",
    "GameStudioRenderer_StudioMergeBones",
    "GameStudioRenderer_StudioRenderModel",
    "GameStudioRenderer_StudioCalcAttachments",
    "GameStudioRenderer_StudioSetupBones",
]
# GCC may outline the diagnostic into a cold clone outside the vtable method.
# Try the method-owned literal first; otherwise use the verified DrawModel body.
FUNC_XREFS = [
    {
        "func_name": "GameStudioRenderer_StudioCalcAttachments",
        "xref_strings": ["FULLMATCH:Too many attachments on %s\n"],
        "xref_gvs": [],
        "xref_signatures": [],
        "xref_funcs": [],
    },
    {
        "func_name": "GameStudioRenderer_StudioSetupBones",
        "xref_strings": ["FULLMATCH:Bip01 Spine"],
        "xref_gvs": [],
        "xref_signatures": [],
        "xref_funcs": [],
    },
]
LLM_DECOMPILE = [
    {
        "symbol_name": name,
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": ["references/{gamever}/client/GameStudioRenderer_StudioDrawModel.{platform}.yaml"],
        "expected_result_sections": ["found_vcall", "found_funcptr"],
        "dependency_policy": {"GameStudioRenderer_StudioDrawModel.{platform}.yaml": "required"},
    }
    for name in TARGET_FUNCTION_NAMES
]
VFUNC_FIELDS = [
    "func_name",
    "func_va",
    "func_rva",
    "func_size",
    "vtable_name",
    "vfunc_index",
    "vfunc_offset",
    "vfunc_sig",
    "vfunc_sig_allow_across_function_boundary:true",
]
GENERATE_YAML_DESIRED_FIELDS = [(name, VFUNC_FIELDS) for name in TARGET_FUNCTION_NAMES]


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
        func_xrefs=FUNC_XREFS,
        func_vtable_relations=[(name, "GameStudioRenderer") for name in TARGET_FUNCTION_NAMES],
        llm_decompile_specs=LLM_DECOMPILE,
        llm_config=llm_config,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )
