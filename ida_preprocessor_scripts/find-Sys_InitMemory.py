#!/usr/bin/env python3
"""Preprocess script for find-Sys_InitMemory."""

from ida_analyze_util import preprocess_common_skill


TARGET_FUNCTION_NAMES = ["Sys_InitMemory"]

# Windows (hl-*/cof-*): fatal low-memory diagnostic inside Sys_InitMemory
# (engine/sys_dll2.cpp). Linux keeps the 15MB wording only in HL25-era builds;
# older Linux engines (hl-8684) drop it, but every hl Linux build parses the
# "-heapsize" command line inside this same function.
ANCHOR_WINDOWS = "FULLMATCH:Available memory less than 15MB!!! %i\n"
ANCHOR_LINUX = "FULLMATCH:-heapsize"

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
