#!/usr/bin/env python3
"""Recover the server-manager singleton and engine field from string-array validation.

Reuse KeepIfPrevious's own array-type diagnostic and the references generated
for Part C. The singleton is loaded, lazily constructed and written back before
its scriptEngine is used to query the array's element type. These two targets
share one LLM context on both Sven versions/platforms; the existing Linux-only
GetTypeInfoByName finder retains its separate platform gating.

The 5.15 ELF load materializes pInstance's address through a relocated GOT slot;
the 5.16 ELF load directly accesses its storage with a GOTOFF displacement.
The shared validator resolves the storage, not the GOT slot or manager object,
and derives gv_pic_addend from the current instruction and validated target.
Never discover through old signatures, symbol names, ordinals or fixed offsets.
The extended output-signature budget covers MSVC SEH and reaches body statements
including the array/null guard; Windows signatures also reach singleton access.
"""

from ida_analyze_util import _load_yaml_mapping, _output_for_symbol, preprocess_common_skill, write_gv_yaml

TARGET_GLOBAL_NAMES = ["g_pServerManager"]
TARGET_STRUCT_MEMBER_NAMES = ["CASServerManager_scriptEngine"]
GLOBAL_IDENTITY = "CASServerManager::GetInstance()::pInstance"
LLM_DECOMPILE = [
    {
        "symbol_name": "g_pServerManager",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": ["references/{gamever}/server/CASPersistence_KeepIfPrevious.{platform}.yaml"],
        "expected_result_sections": ["found_gv"],
        "dependency_policy": {"CASPersistence_KeepIfPrevious.{platform}.yaml": "required"},
    },
    {
        "symbol_name": "CASServerManager_scriptEngine",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": ["references/{gamever}/server/CASPersistence_KeepIfPrevious.{platform}.yaml"],
        "expected_result_sections": ["found_struct_offset"],
        "dependency_policy": {"CASPersistence_KeepIfPrevious.{platform}.yaml": "required"},
        "expected_size": 4,
    },
]
GENERATE_YAML_DESIRED_FIELDS = [
    (
        "g_pServerManager",
        [
            "gv_name",
            "gv_va",
            "gv_rva",
            "gv_sig",
            "gv_sig_va",
            "gv_inst_offset",
            "gv_inst_length",
            "gv_inst_disp",
            "gv_sig_allow_across_function_boundary:true",
        ],
    ),
    (
        "CASServerManager_scriptEngine",
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
    success = await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=None,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        gv_names=TARGET_GLOBAL_NAMES,
        struct_member_names=TARGET_STRUCT_MEMBER_NAMES,
        llm_decompile_specs=LLM_DECOMPILE,
        llm_config=llm_config,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )
    if success:
        output = _output_for_symbol(expected_outputs, "g_pServerManager")
        payload = _load_yaml_mapping(output)
        payload["gv_name"] = GLOBAL_IDENTITY
        write_gv_yaml(output, payload)
    return success
