#!/usr/bin/env python3
"""Recover NET_IsLocalAddress from the local-address bypass in SV_CheckChallenge.

The predecessor's own NULL-address diagnostic is deterministic. Compact predicate
signatures either collide or exceed the four-pattern coverage budget across MSVC,
GCC, BLOB and CoF. The annotated call is validated in the current predecessor;
generated signatures are output checks only. The argument is a by-value netadr_t:
20 bytes in HL/CoF, 36 in the configured SvEngine inputs, despite narrow Hex-Rays
pseudo-prototypes. HL 8684/10210 accept exact 127.0.0.1; other inputs only loopback.
"""

from ida_analyze_util import preprocess_common_skill
from ida_preprocessor_scripts._native_rcon_common import preserve_function_identities

NAME = "NET_IsLocalAddress"
LLM_DECOMPILE = [
    {
        "symbol_name": "NET_IsLocalAddress",
        "prompt_path": "prompt/call_llm_decompile.md",
        "reference_yaml_paths": ["references/{gamever}/engine/SV_CheckChallenge.{platform}.yaml"],
        "expected_result_sections": ["found_call"],
        "dependency_policy": {"SV_CheckChallenge.{platform}.yaml": "required"},
    },
]
FIELDS = [
    "func_name",
    "func_va",
    "func_rva",
    "func_size",
    "func_sig",
    "func_sig_allow_across_function_boundary:true",
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
    found = await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=None,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_names=[NAME],
        llm_decompile_specs=LLM_DECOMPILE,
        llm_config=llm_config,
        generate_yaml_desired_fields=[(NAME, FIELDS)],
        debug=debug,
    )
    return found and await preserve_function_identities(
        session, expected_outputs, new_binary_dir, platform, image_base, [NAME]
    )
