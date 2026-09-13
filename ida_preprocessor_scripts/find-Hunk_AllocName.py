#!/usr/bin/env python3
"""Locate Hunk_AllocName through its allocator-guard literal.

engine/cmodel / hunk code aborts through ``Hunk_Alloc: bad size`` when the
requested size is negative; the literal belongs to Hunk_AllocName only. The
svencoop-10257 Linux branch has no single-owner string anchor for this
function: that branch is produced by find-Mod_LoadSpriteModel-decompiles and
this skill is platform-gated to Windows in the svencoop-10257 config.
"""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = ["Hunk_AllocName"]
FUNC_XREFS = [
    {
        "func_name": "Hunk_AllocName",
        "xref_strings": ["FULLMATCH:Hunk_Alloc: bad size: %i"],
        "xref_gvs": [],
        "xref_signatures": [],
        "xref_funcs": [],
    },
]
GENERATE_YAML_DESIRED_FIELDS = [
    ("Hunk_AllocName", ["func_name", "func_sig", "func_va", "func_rva", "func_size"]),
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
