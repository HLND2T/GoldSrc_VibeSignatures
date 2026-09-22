#!/usr/bin/env python3
"""Recover the current and previous view-leaf pointer globals from R_MarkLeaves.

The same-leaf early return, r_oldviewleaf = r_viewleaf assignment, and
Mod_LeafPVS(r_viewleaf, cl.worldmodel) argument distinguish the two slots.
Reuse the existing R_MarkLeaves producer on every configured engine build.
SvEngine Linux 8948 loads their addresses through GOT slots; 10257 uses PIC
LEA operands. Resolve the globals themselves, not the GOT slots or pointees.
"""

from ida_analyze_util import preprocess_common_skill

TARGET_GLOBAL_NAMES = ["r_viewleaf", "r_oldviewleaf"]
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
LLM_DECOMPILE = [
    {
        "symbol_name": name,
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": ["references/{gamever}/engine/R_MarkLeaves.{platform}.yaml"],
        "expected_result_sections": ["found_gv"],
        "dependency_policy": {"R_MarkLeaves.{platform}.yaml": "required"},
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
