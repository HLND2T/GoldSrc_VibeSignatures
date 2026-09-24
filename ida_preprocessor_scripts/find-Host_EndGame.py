#!/usr/bin/env python3
"""Locate Host_EndGame by its own diagnostic format string.

Older Windows builds keep two copies of the exact format string, but both
references are in Host_EndGame. The shared string-xref finder merges their
owning function candidates and requires one unique function.
"""

from ida_analyze_util import preprocess_common_skill

FUNC_NAME = "Host_EndGame"
FUNC_XREFS = [{"func_name": FUNC_NAME, "xref_strings": ["FULLMATCH:Host_EndGame: %s\n"]}]
FUNC_FIELDS = [
    (
        FUNC_NAME,
        ["func_name", "func_sig", "func_va", "func_rva", "func_size", "func_sig_allow_across_function_boundary:true"],
    )
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
        func_names=[FUNC_NAME],
        func_xrefs=FUNC_XREFS,
        generate_yaml_desired_fields=FUNC_FIELDS,
        debug=debug,
    )
