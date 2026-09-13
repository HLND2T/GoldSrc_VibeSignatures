#!/usr/bin/env python3
"""Locate Cache_Alloc through its cache-owner diagnostic literal.

engine/cache.c prints ``Cache_Alloc: size %i`` when the allocated block would
leave no contiguous tail in the zone; the literal belongs to Cache_Alloc only.
"""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = ["Cache_Alloc"]
FUNC_XREFS = [
    {
        "func_name": "Cache_Alloc",
        "xref_strings": ["FULLMATCH:Cache_Alloc: size %i"],
        "xref_gvs": [],
        "xref_signatures": [],
        "xref_funcs": [],
    },
]
GENERATE_YAML_DESIRED_FIELDS = [
    ("Cache_Alloc", ["func_name", "func_sig", "func_va", "func_rva", "func_size"]),
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
