#!/usr/bin/env python3
"""Locate Mod_LoadBrushModel through its BSP version-check literal.

engine/model loading rejects a brush model whose BSP version differs from
BSPVERSION with ``Mod_LoadBrushModel: %s has wrong version number (%i should
be %i)``; the literal belongs to Mod_LoadBrushModel only. The
svencoop-10257 Linux branch has no single-owner string anchor for this
function: that branch is produced by find-Mod_LoadModel-brushmodel-decompiles
and this skill is platform-gated to Windows in the svencoop-10257 config.
"""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = ["Mod_LoadBrushModel"]
FUNC_XREFS = [
    {
        "func_name": "Mod_LoadBrushModel",
        "xref_strings": ["FULLMATCH:Mod_LoadBrushModel: %s has wrong version number (%i should be %i)\n"],
        "xref_gvs": [],
        "xref_signatures": [],
        "xref_funcs": [],
    },
]
GENERATE_YAML_DESIRED_FIELDS = [
    ("Mod_LoadBrushModel", ["func_name", "func_sig", "func_va", "func_rva", "func_size"]),
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
