#!/usr/bin/env python3
"""Recover the player-extra array from the ScoreInfo frags store at member zero.

CS/CZ share CounterStrikeViewport's message handler; CZDS uses the distinct
TeamFortressViewport body and layout. Neither exists in canonical Half-Life,
so each body has one explicit reference family, shared across its builds.
"""

from ida_analyze_util import _output_for_symbol, preprocess_common_skill

GV_FIELDS = [
    "gv_name",
    "gv_va",
    "gv_rva",
    "gv_sig",
    "gv_sig_va",
    "gv_inst_offset",
    "gv_inst_length",
    "gv_inst_disp",
    "gv_sig_allow_across_function_boundary:true",
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
    czds = _output_for_symbol(expected_outputs, "g_PlayerExtraInfo_CZDS") is not None
    name = "g_PlayerExtraInfo_CZDS" if czds else "g_PlayerExtraInfo"
    family = "czeror-10210" if czds else "cstrike-10210"
    specs = [
        {
            "symbol_name": name,
            "prompt_path": "prompt/call_llm_decompile.md",
            "reference_yaml_paths": [f"references/{family}/client/ClientScoreInfoHandler.{{platform}}.yaml"],
            "expected_result_sections": ["found_gv"],
            "dependency_policy": {"ClientScoreInfoHandler.{platform}.yaml": "required"},
        }
    ]
    return await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=None,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        gv_names=[name],
        llm_decompile_specs=specs,
        llm_config=llm_config,
        generate_yaml_desired_fields=[(name, GV_FIELDS)],
        debug=debug,
    )
