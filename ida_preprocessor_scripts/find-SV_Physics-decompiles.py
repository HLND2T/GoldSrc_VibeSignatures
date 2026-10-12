#!/usr/bin/env python3
"""Recover the MOVETYPE_PUSH calls owned by the frame physics dispatcher.

Classic Windows and all configured ELF builds call SV_Physics_Pusher. HL25
Windows and SvEngine Windows inline that helper, so their dispatcher directly
calls SV_PushMove. Never label the dispatcher itself as a pusher function.
"""

from ida_analyze_util import _output_for_symbol, preprocess_common_skill
from llm_spec import select_llm_specs

LLM_DECOMPILE = {
    "standalone": [
        {
            "symbol_name": "SV_Physics_Pusher",
            "prompt_path": "prompt/call_llm_decompile.md",
            "reference_yaml_paths": ["references/hl-8684/engine/SV_Physics.{platform}.yaml"],
            "expected_result_sections": ["found_call"],
            "dependency_policy": {"SV_Physics.{platform}.yaml": "required"},
        },
    ],
    "inlined": [
        {
            "symbol_name": "SV_PushMove",
            "prompt_path": "prompt/call_llm_decompile.md",
            "reference_yaml_paths": ["references/{gamever}/engine/SV_Physics.{platform}.yaml"],
            "expected_result_sections": ["found_call"],
            "dependency_policy": {"SV_Physics.{platform}.yaml": "required"},
        },
    ],
}


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
    name = "SV_PushMove" if _output_for_symbol(expected_outputs, "SV_PushMove") else "SV_Physics_Pusher"
    specs = select_llm_specs(LLM_DECOMPILE, branch="inlined" if name == "SV_PushMove" else "standalone")
    return await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=None,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_names=[name],
        llm_decompile_specs=specs,
        llm_config=llm_config,
        generate_yaml_desired_fields=[(name, ["func_name", "func_va", "func_rva", "func_size", "func_sig"])],
        debug=debug,
    )
