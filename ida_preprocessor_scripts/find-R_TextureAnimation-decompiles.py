#!/usr/bin/env python3
"""Recover the function-local random animation table, not the initialization end pointer."""

from ida_analyze_util import preprocess_common_skill
from ida_preprocessor_scripts.renderer_elf_symbols import preserve_global_identities

LLM_DECOMPILE = [
    {
        "symbol_name": "rtable",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": ["references/{gamever}/engine/R_TextureAnimation.{platform}.yaml"],
        "expected_result_sections": ["found_gv"],
        "dependency_policy": {"R_TextureAnimation.{platform}.yaml": "required"},
    }
]
FIELDS = ["gv_name", "gv_va", "gv_rva", "gv_sig", "gv_sig_va", "gv_inst_offset", "gv_inst_length", "gv_inst_disp"]


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
    success = await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=None,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        gv_names=["rtable"],
        llm_decompile_specs=LLM_DECOMPILE,
        llm_config=llm_config,
        generate_yaml_desired_fields=[("rtable", FIELDS)],
        debug=debug,
    )
    return success and await preserve_global_identities(session, expected_outputs, platform)
