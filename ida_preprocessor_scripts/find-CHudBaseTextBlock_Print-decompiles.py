#!/usr/bin/env python3
"""Recover the viewport pointer and the sound-engine singleton storage.

The verified Print body gates chat through gViewPort->AllowedToPrintText and
loads/stores CClient_SoundEngine::m_pSoundEngine around its lazy construction.
This emits the pointer variable, not a callable getter: reading it does not
initialize the sound engine."""

from ida_analyze_util import preprocess_common_skill

TARGET_GLOBAL_NAMES = ["gViewPort", "CClient_SoundEngine_m_pSoundEngine"]
LLM_DECOMPILE = [
    {
        "symbol_name": name,
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": ["references/{gamever}/client/CHudBaseTextBlock_Print.{platform}.yaml"],
        "expected_result_sections": ["found_gv"],
        "dependency_policy": {"CHudBaseTextBlock_Print.{platform}.yaml": "required"},
    }
    for name in TARGET_GLOBAL_NAMES
]
FIELDS = ["gv_name", "gv_va", "gv_rva", "gv_sig", "gv_sig_va", "gv_inst_offset", "gv_inst_length", "gv_inst_disp"]
GENERATE_YAML_DESIRED_FIELDS = [(name, FIELDS) for name in TARGET_GLOBAL_NAMES]


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
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )
