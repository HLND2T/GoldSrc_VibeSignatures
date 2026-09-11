#!/usr/bin/env python3
"""Recover the parse counter used to select the transparent player's frame."""

import re

from ida_analyze_util import preprocess_common_skill

LLM_DECOMPILE = [
    {
        "symbol_name": "cl_parsecount",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": ["references/{gamever}/engine/R_DrawTEntitiesOnList.{platform}.yaml"],
        "expected_result_sections": ["found_gv"],
        "dependency_policy": {"R_DrawTEntitiesOnList.{platform}.yaml": "required"},
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

# cl_parsecount is always named directly: an absolute operand naming the symbol
# (optionally with a member-free byte offset) or the Linux PIC form
# `(symbol - base)[reg]`. Register-relative accesses such as `[esi+242324h]`
# name a different object's member (the update-mask value, the currententity
# index, or the frame stride) that the reference forbids, so pin the shape.
_REGISTER32 = r"e(?:ax|bx|cx|dx|si|di|bp|sp)"
_IDENTIFIER = r"[A-Za-z_?$][\w.$?@]*"
_ANONYMOUS = r"(?:byte|word|dword|qword|off|unk|flt|dbl|sub)_[0-9A-Fa-f]+"
_SYMBOL = rf"(?:{_IDENTIFIER}|{_ANONYMOUS})"
_SIZE_PREFIX = r"(?:(?:byte|word|dword|qword|large)\s+ptr\s+|(?:byte|word|dword|qword|large)\s+)?"
_OFFSET = r"(?:0x[0-9A-Fa-f]+|[0-9A-Fa-f]+h)"
_NOT_REGISTER = rf"(?!(?:{_REGISTER32}|xmm\d+|st(?:\(\d\))?)\b)"
_LINUX_GLOBAL_REFERENCE = re.compile(
    rf"(?i)(?:"
    rf"(?:mov|movzx|movsx|lea)\s+\w+,\s*{_SIZE_PREFIX}(?:ds:)?{_NOT_REGISTER}{_IDENTIFIER}"
    rf"(?:\s*[+\-]\s*{_OFFSET})?"
    rf"|"
    rf"(?:mov|movzx|movsx|lea)\s+\w+,\s*{_SIZE_PREFIX}\(\s*{_SYMBOL}\s*[+\-]\s*{_OFFSET}\s*\)"
    rf"\s*\[\s*{_REGISTER32}\s*\]"
    rf")"
)
_LINUX_INSTRUCTION_RULES = [
    {
        "regex": _LINUX_GLOBAL_REFERENCE.pattern,
        "text": (
            "Select only a direct cl_parsecount global reference: an absolute operand "
            "naming the symbol itself (mov reg, [ds:]symbol[+offset]) or the Linux PIC "
            "form (symbol - base)[reg]. Reject register-relative member accesses such as "
            "[reg+offset]; those name the update-mask value, currententity index, or "
            "frame stride."
        ),
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
    spec = dict(LLM_DECOMPILE[0])
    if platform == "linux":
        spec["instruction_rules"] = _LINUX_INSTRUCTION_RULES
    return await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=None,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        gv_names=["cl_parsecount"],
        llm_decompile_specs=[spec],
        llm_config=llm_config,
        generate_yaml_desired_fields=[("cl_parsecount", GV_FIELDS)],
        debug=debug,
    )
