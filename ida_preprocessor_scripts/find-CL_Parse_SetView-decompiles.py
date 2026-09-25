#!/usr/bin/env python3
"""Recover the server-selected view-entity index, not the viewmodel entity."""

from ida_analyze_util import preprocess_common_skill

LLM_DECOMPILE = [
    {
        "symbol_name": "cl_viewentity",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": ["references/{gamever}/engine/CL_Parse_SetView.{platform}.yaml"],
        "expected_result_sections": ["found_gv"],
        "instruction_rules": [
            {
                # IDA may omit DS for absolute memory symbols on Windows.
                # A bare register remains a copy, not the required field store.
                "regex": (
                    r"(?i)mov\s+(?:dword ptr\s+)?(?:ds:[^,]+|[^,]*\[[^\]]+\]|"
                    r"(?!e(?:ax|bx|cx|dx|si|di|bp|sp)\b)[a-z_?$@][\w?$@.]*),\s*eax"
                ),
                "text": (
                    "Select the memory store of MSG_ReadShort()'s EAX result to cl.viewentity. "
                    "Reject register loads of the containing client-state/PIC/GOT base. "
                    "For a base-relative store, preserve the actual displacement; the effective "
                    "field address is resolved from the current instructions."
                ),
            }
        ],
        "dependency_policy": {"CL_Parse_SetView.{platform}.yaml": "required"},
    }
]
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
    return await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=None,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        gv_names=["cl_viewentity"],
        llm_decompile_specs=LLM_DECOMPILE,
        llm_config=llm_config,
        generate_yaml_desired_fields=[("cl_viewentity", GV_FIELDS)],
        debug=debug,
    )
