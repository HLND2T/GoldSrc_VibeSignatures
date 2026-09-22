#!/usr/bin/env python3
"""Recover the four engine matrices from the existing R_SetupGL predecessor.

GetFloatv(GL_PROJECTION_MATRIX) and GetFloatv(GL_MODELVIEW_MATRIX) distinguish
the two input matrices. Their product is gWorldToScreen, also passed as the
input to InvertMatrix; its output is gScreenToWorld. These are float[16]
objects, not pointers or individual matrix elements. Reuse that dataflow
across GoldSrc, HL25, SvEngine and decrypted BLOB builds without call ordinals
or fixed windows. Linux SvEngine operands require the shared PIC resolver.
"""

from ida_analyze_util import preprocess_common_skill

TARGET_GLOBAL_NAMES = ["gWorldToScreen", "gScreenToWorld", "gProjectionMatrix", "r_world_matrix"]
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
MATRIX_ARGUMENT_RULES = [
    {
        "regex": (
            r"(?i)(?:push\s+(?:offset\s+)?\w+"
            r"|mov\s+(?:dword ptr\s+)?\[esp[^\]]*\],\s+(?:offset\s+)?\w+"
            r"|mov\s+\w+,\s+offset\s+\w+"
            r"|lea\s+\w+,\s+(?:ds:)?"
            r"(?:\([^,+\[\]]+\s-\s[^,\[\]]+\)\[ebx\]|\[ebx[+-][^,\[\]]+\]))"
        ),
        "text": (
            "Select only the instruction preparing this complete matrix's address as a call argument: "
            "the output pointer of GetFloatv for gProjectionMatrix/r_world_matrix, or the input/output "
            "pointer of InvertMatrix for gWorldToScreen/gScreenToWorld. On PIC targets, select the "
            "object-address LEA feeding that argument. Do not return matrix-element/vector loads or "
            "stores, indexed loop addresses, or interior rows: their operands can encode base+16 instead "
            "of the array base. Trace the argument role, never a fixed call ordinal."
        ),
    }
]
LLM_DECOMPILE = [
    {
        "symbol_name": name,
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": ["references/{gamever}/engine/R_SetupGL.{platform}.yaml"],
        "expected_result_sections": ["found_gv"],
        "dependency_policy": {"R_SetupGL.{platform}.yaml": "required"},
        "instruction_rules": MATRIX_ARGUMENT_RULES,
    }
    for name in TARGET_GLOBAL_NAMES
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
        gv_names=TARGET_GLOBAL_NAMES,
        llm_decompile_specs=LLM_DECOMPILE,
        llm_config=llm_config,
        generate_yaml_desired_fields=[(name, GV_FIELDS) for name in TARGET_GLOBAL_NAMES],
        debug=debug,
    )
