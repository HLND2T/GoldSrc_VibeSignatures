#!/usr/bin/env python3
"""Recover sv_areanodes from the confirmed SV_LinkEdict diagnostic owner.

The global is selected from its current data access, never a reference address
or an old artifact signature. The downstream layout finder independently
validates the table/tree/group behavior before publishing derived values.
"""

from ida_analyze_util import preprocess_common_skill
from ida_preprocessor_scripts._server_physics_common import finish_globals

LLM_DECOMPILE = [
    {
        "symbol_name": "sv_areanodes",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": ["references/{gamever}/engine/SV_LinkEdict.{platform}.yaml"],
        "expected_result_sections": ["found_gv"],
        "dependency_policy": {"SV_LinkEdict.{platform}.yaml": "required"},
    }
]
NAMES = ["sv_areanodes"]
FIELDS = [
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
    found = await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=None,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        gv_names=NAMES,
        llm_decompile_specs=LLM_DECOMPILE,
        llm_config=llm_config,
        generate_yaml_desired_fields=[(name, FIELDS) for name in NAMES],
        debug=debug,
    )
    return found and await finish_globals(session, expected_outputs, platform)
