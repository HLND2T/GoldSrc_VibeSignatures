#!/usr/bin/env python3
"""Recover Sven's pitch-drift object from the zero-offset pitchvel access."""

import re

from ida_analyze_util import _export_llm_function, _prepare_llm_context, preprocess_common_skill
from ida_llm_decompile import _build_target_disasm_index

# Both supported Sven bodies assign v_centerspeed->value to pitchvel with
# one scalar-float global store. Stack transfers and loads are not anchors.
_GLOBAL_LABEL = r"(?!xmm[0-7]\b)[A-Za-z_?$][\w.$?@]*"
_PITCHVEL_STORE_RE = re.compile(
    rf"movss\s+(?:dword ptr\s+)?(?:ds:)?(?:{_GLOBAL_LABEL}|"
    rf"\({_GLOBAL_LABEL}\s*-\s*(?:0x[0-9a-f]+|[0-9a-f]+h)\)\[e(?:ax|bx|cx|dx|si|di|bp)\]),\s*xmm[0-7]",
    re.I,
)

LLM_DECOMPILE = [
    {
        "symbol_name": "g_pitchdrift",
        "prompt_path": "prompt/call_llm_pitchdrift.md",
        "reference_yaml_paths": ["references/{gamever}/client/V_StartPitchDrift.{platform}.yaml"],
        "expected_result_sections": ["found_gv"],
        "dependency_policy": {"V_StartPitchDrift.{platform}.yaml": "required"},
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
    spec = dict(LLM_DECOMPILE[0])
    context = _prepare_llm_context(spec, llm_config, new_binary_dir, platform)
    if context is None or len(context["targets"]) != 1:
        return False
    exported = await _export_llm_function(session, context["targets"][0][1])
    instructions, _ = _build_target_disasm_index((exported or {}).get("disasm_code", ""))
    stores = [line for lines in instructions.values() for line in lines if _PITCHVEL_STORE_RE.fullmatch(line)]
    if len(stores) != 1:
        print("PitchDrift: expected one scalar-float global store in V_StartPitchDrift")
        return False
    spec["instruction_rules"] = [
        {
            "regex": r"(?i)" + r"\s+".join(re.escape(part) for part in stores[0].split()),
            "text": (
                "Return only the pitchvel global store of v_centerspeed->value: "
                + stores[0]
                + ". Reject laststop/nodrift/driftmove members and all loads, including pitchvel loads."
            ),
        }
    ]
    return await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=None,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        gv_names=["g_pitchdrift"],
        llm_decompile_specs=[spec],
        llm_config=llm_config,
        generate_yaml_desired_fields=[("g_pitchdrift", GV_FIELDS)],
        debug=debug,
    )
