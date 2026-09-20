#!/usr/bin/env python3
"""Recover the world frame counters from the recursive world node walk.

``R_RecursiveWorldNode`` rejects a node whose ``visframe`` does not match
``r_visframecount`` and stamps surviving leaves and surfaces with
``r_framecount``. Both counters are plain ``int`` globals.

The two addresses are unrelated (adjacent on SvEngine, 0x7c apart on HL25), so
each is recovered by its own LLM target rather than derived from the other.
Discovery never consumes an old artifact signature.
"""

from ida_analyze_util import preprocess_common_skill

TARGET_GLOBAL_NAMES = ["r_framecount", "r_visframecount"]
PREDECESSOR = "R_RecursiveWorldNode"
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
LLM_DECOMPILE = [
    {
        "symbol_name": name,
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": [f"references/{{gamever}}/engine/{PREDECESSOR}.{{platform}}.yaml"],
        "expected_result_sections": ["found_gv"],
        "dependency_policy": {f"{PREDECESSOR}.{{platform}}.yaml": "required"},
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
