#!/usr/bin/env python3
"""Locate Mod_PointInLeaf through its null-node guard literal.

engine/model lookup aborts with ``Mod_PointInLeaf: bad model`` when the
model has no nodes; the literal belongs to Mod_PointInLeaf only.
"""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = ["Mod_PointInLeaf"]
FUNC_XREFS = [
    {
        "func_name": "Mod_PointInLeaf",
        "xref_strings": ["FULLMATCH:Mod_PointInLeaf: bad model"],
        "xref_gvs": [],
        "xref_signatures": [],
        "xref_funcs": [],
    },
]
GENERATE_YAML_DESIRED_FIELDS = [
    ("Mod_PointInLeaf", ["func_name", "func_sig", "func_va", "func_rva", "func_size"]),
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
