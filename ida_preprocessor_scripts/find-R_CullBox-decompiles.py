#!/usr/bin/env python3
"""Recover the four-plane array base, not a plane member or the loop end.

HL-8684 Linux unrolls the four BoxOnPlaneSide calls. SvEngine Linux uses
PIC addressing. The verified current R_CullBox body owns every selected access.
"""

from ida_analyze_util import preprocess_common_skill

LLM_DECOMPILE = [
    {
        "symbol_name": "frustum",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": ["references/{gamever}/engine/R_CullBox.{platform}.yaml"],
        "expected_result_sections": ["found_gv"],
        "dependency_policy": {"R_CullBox.{platform}.yaml": "required"},
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
        gv_names=["frustum"],
        llm_decompile_specs=LLM_DECOMPILE,
        llm_config=llm_config,
        generate_yaml_desired_fields=[
            (
                "frustum",
                [
                    "gv_name",
                    "gv_va",
                    "gv_rva",
                    "gv_sig",
                    "gv_sig_va",
                    "gv_inst_offset",
                    "gv_inst_length",
                    "gv_inst_disp",
                ],
            )
        ],
        debug=debug,
    )
