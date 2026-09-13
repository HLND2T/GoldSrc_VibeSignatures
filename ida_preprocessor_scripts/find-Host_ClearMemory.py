#!/usr/bin/env python3
"""Locate Host_ClearMemory through its memory-scrub literal.

engine/host.c reports ``Clearing memory`` while freeing the hunk, cache and
model state; the literal belongs to Host_ClearMemory only.
"""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = ["Host_ClearMemory"]
FUNC_XREFS = [
    {
        "func_name": "Host_ClearMemory",
        "xref_strings": ["FULLMATCH:Clearing memory\n"],
        "xref_gvs": [],
        "xref_signatures": [],
        "xref_funcs": [],
    },
]
GENERATE_YAML_DESIRED_FIELDS = [
    ("Host_ClearMemory", ["func_name", "func_sig", "func_va", "func_rva", "func_size"]),
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
    _ = skill_name, old_yaml_map
    return await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=None,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_names=TARGET_FUNCTION_NAMES,
        func_xrefs=FUNC_XREFS,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )
