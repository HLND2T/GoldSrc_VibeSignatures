#!/usr/bin/env python3
"""Locate R_LoadSkys through its sky-face banner literal.

engine/gl_warp.c prints ``SKY:  `` (two trailing spaces, no newline) before
loading the six sky faces; the HL/CoF literal belongs to R_LoadSkys only.
SvEngine prints a one-space variant owned by its internal loader, so this
finder is not registered for svencoop-10257.
"""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = ["R_LoadSkys"]
FUNC_XREFS = [
    {
        "func_name": "R_LoadSkys",
        "xref_strings": ["FULLMATCH:SKY:  "],
        "xref_gvs": [],
        "xref_signatures": [],
        "xref_funcs": [],
    },
]
GENERATE_YAML_DESIRED_FIELDS = [
    ("R_LoadSkys", ["func_name", "func_sig", "func_va", "func_rva", "func_size"]),
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
