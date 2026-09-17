#!/usr/bin/env python3
"""Locate FS_Open and the loading-state globals from the Mod_LoadModel reference.

``Mod_LoadModel`` sets ``loadname`` (the ``COM_FileBase`` output buffer) and
``loadmodel`` (the model being loaded) just before it dispatches on the model
header, so the annotated predecessor body pins both global accesses.  The
access encoding differs per family/platform (``push offset`` on MSVC,
``mov reg, offset`` on non-PIC ELF, ``lea``/``mov`` GOTOFF on PIC ELF), which is
exactly what the LLM-selected instruction handles without a per-form locator.
"""

from ida_analyze_util import preprocess_common_skill


TARGET_FUNCTION_NAMES = ["FS_Open"]
TARGET_GLOBAL_NAMES = ["loadname", "loadmodel"]

REFERENCE_YAML_PATHS = [
    "references/{gamever}/engine/Mod_LoadModel.{platform}.yaml",
]
DEPENDENCY_POLICY = {
    "Mod_LoadModel.{platform}.yaml": "required",
}

LLM_DECOMPILE = [
    {
        "symbol_name": "FS_Open",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": REFERENCE_YAML_PATHS,
        "expected_result_sections": ["found_call"],
        "dependency_policy": DEPENDENCY_POLICY,
    },
] + [
    {
        "symbol_name": name,
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": REFERENCE_YAML_PATHS,
        "expected_result_sections": ["found_gv"],
        "dependency_policy": DEPENDENCY_POLICY,
    }
    for name in TARGET_GLOBAL_NAMES
]

FUNC_FIELDS = ["func_name", "func_sig", "func_va", "func_rva", "func_size"]
GV_FIELDS = [
    "gv_name",
    "gv_va",
    "gv_rva",
    "gv_sig",
    "gv_sig_va",
    "gv_inst_offset",
    "gv_inst_length",
    "gv_inst_disp",
]

GENERATE_YAML_DESIRED_FIELDS = [
    ("FS_Open", FUNC_FIELDS),
] + [(name, GV_FIELDS) for name in TARGET_GLOBAL_NAMES]


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
        gv_names=TARGET_GLOBAL_NAMES,
        llm_decompile_specs=LLM_DECOMPILE,
        llm_config=llm_config,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )
