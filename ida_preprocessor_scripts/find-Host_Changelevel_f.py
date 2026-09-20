#!/usr/bin/env python3
"""Locate Host_Changelevel_f through its exact command-help string.

The command registration/help text is owned by Host_Changelevel_f across the
supported GoldSrc and SvEngine engine builds. Exact matching keeps the anchor
separate from unrelated changelevel diagnostics and command-line text.
"""

from ida_analyze_util import preprocess_common_skill


TARGET_FUNCTION_NAMES = ["Host_Changelevel_f"]
FUNC_XREFS = [
    {
        "func_name": "Host_Changelevel_f",
        "xref_strings": ["FULLMATCH:changelevel <levelname> : continue game on a new level\n"],
        "xref_gvs": [],
        "xref_signatures": [],
        "xref_funcs": [],
    },
]
GENERATE_YAML_DESIRED_FIELDS = [
    ("Host_Changelevel_f", ["func_name", "func_sig", "func_va", "func_rva", "func_size"]),
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
