#!/usr/bin/env python3
"""Locate R_DrawSpriteModel through its own sprite-frame diagnostic.

``R_DrawSpriteModel`` draws one sprite polygon for the entity being rendered.
It owns the frame lookup, the ``r_blend`` normal-render assignment and the
sprite quad emission. Discovery never consumes an old artifact signature.

The literal below is referenced from inside ``R_DrawSpriteModel`` itself, so a
data xref on it names the owning function directly. It is invariant across every
configured engine family and platform, including the BLOB builds that are
analyzed through ``hw.decrypt.dll``.
"""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = ["R_DrawSpriteModel"]
FUNC_XREFS = [
    {
        "func_name": "R_DrawSpriteModel",
        "xref_strings": ["FULLMATCH:R_DrawSpriteModel:  couldn't get sprite frame for %s\n"],
        "xref_gvs": [],
        "xref_signatures": [],
        "xref_funcs": [],
    },
]
GENERATE_YAML_DESIRED_FIELDS = [
    ("R_DrawSpriteModel", ["func_name", "func_sig", "func_va", "func_rva", "func_size"]),
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
