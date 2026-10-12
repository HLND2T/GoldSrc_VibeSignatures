#!/usr/bin/env python3
"""Recover CASServerManager's inherited current-module field from OnMapEnd.

Reuse the existing active-module diagnostic anchor and Part A references. The
field is checked before that diagnostic and cleared afterward. CASServerManager
constructs CASBaseManager at the same object address on all four inputs, so this
is its inherited curModule field, not a global or the separate moduleHandle.
References retain the base view's activeModule name and explicitly map its role
to the consumer's curModule name. Unknown class fields and total size remain
unpublished. No reference build's displacement is used as a discovery value.
The extended output-signature budget accommodates the MSVC SEH header and reaches
the map-end hook's argument setup in the current body.
"""

from ida_analyze_util import preprocess_common_skill

TARGET_STRUCT_MEMBER_NAMES = ["CASServerManager_curModule"]
LLM_DECOMPILE = [
    {
        "symbol_name": "CASServerManager_curModule",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": ["references/{gamever}/server/CASBaseManager_OnMapEnd.{platform}.yaml"],
        "expected_result_sections": ["found_struct_offset"],
        "dependency_policy": {"CASBaseManager_OnMapEnd.{platform}.yaml": "required"},
        "expected_size": 4,
    },
]
GENERATE_YAML_DESIRED_FIELDS = [
    (
        "CASServerManager_curModule",
        [
            "struct_name",
            "member_name",
            "offset",
            "size",
            "offset_sig",
            "offset_sig_disp",
            "offset_sig_allow_across_function_boundary:true",
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
    return await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=None,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        struct_member_names=TARGET_STRUCT_MEMBER_NAMES,
        llm_decompile_specs=LLM_DECOMPILE,
        llm_config=llm_config,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )
