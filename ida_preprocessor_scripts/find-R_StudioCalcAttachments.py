#!/usr/bin/env python3
"""Locate R_StudioCalcAttachments through its own diagnostic/name literal.

The attachment-count diagnostic belongs to this function.
Discovery never consumes an old artifact signature.
"""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = ["R_StudioCalcAttachments"]
FUNC_XREFS = [
    {
        "func_name": "R_StudioCalcAttachments",
        "xref_strings": ["FULLMATCH:Too many attachments on %s\n"],
        "xref_gvs": [],
        "xref_signatures": [],
        "xref_funcs": [],
        # GCC inlines attachment calculation into both draw implementations.
        "exclude_funcs": ["R_StudioDrawModel"],
        "exclude_strings": ["FULLMATCH:models/player/%s/%s.mdl"],
    },
]
GENERATE_YAML_DESIRED_FIELDS = [
    ("R_StudioCalcAttachments", ["func_name", "func_sig", "func_va", "func_rva", "func_size"]),
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
