#!/usr/bin/env python3
"""Preprocess script for Sven Coop's Sys_InitMemory finder."""

from ida_analyze_util import preprocess_common_skill


TARGET_FUNCTION_NAMES = ["Sys_InitMemory"]

# SvEngine Windows reworded the low-memory diagnostic; the SvEngine Linux
# build dropped it entirely and reads /proc/meminfo inside the same function.
ANCHOR_WINDOWS = (
    "FULLMATCH:Available memory less than the %.2f MB requirement (%.2f MB).\n"
    "Check your hardware against the system requirements.\n"
)
ANCHOR_LINUX = "FULLMATCH:/proc/meminfo"

GENERATE_YAML_DESIRED_FIELDS = [
    (
        "Sys_InitMemory",
        ["func_name", "func_sig", "func_va", "func_rva", "func_size"],
    ),
]


async def preprocess_skill(
    session,
    skill_name,
    expected_outputs,
    old_yaml_map,
    new_binary_dir,
    platform,
    image_base,
    debug=False,
):
    _ = skill_name
    func_xrefs = [
        {
            "func_name": "Sys_InitMemory",
            "xref_strings": [ANCHOR_WINDOWS if platform == "windows" else ANCHOR_LINUX],
            "xref_gvs": [],
            "xref_signatures": [],
            "xref_funcs": [],
            "exclude_funcs": [],
            "exclude_strings": [],
            "exclude_gvs": [],
            "exclude_signatures": [],
        },
    ]
    return await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=None,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_names=TARGET_FUNCTION_NAMES,
        func_xrefs=func_xrefs,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )
