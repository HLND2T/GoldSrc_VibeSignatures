#!/usr/bin/env python3
"""Locate GlowBlend (previously emitted as R_GlowBlend) through its falloff constants.

engine/r_trans.c GlowBlend owns three in-body constants:

    brightness = 19000 / (dist*dist);      // falloff magic number
    if (brightness < 0.05) ...
    pEntity->curstate.scale = dist * (1.0/200.0);   // folded to 0.005

The function referencing all three constants is unique on every validated
build that keeps GlowBlend as a standalone function (GoldSrc/CoF both
platforms, HL25 and SvEngine Linux). HL25 and SvEngine Windows builds inline
GlowBlend into R_DrawTEntitiesOnList, so on those game versions the symbol is
config-gated to Linux instead of emitting the inlined host.
"""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = ["GlowBlend"]
FUNC_XREFS = [
    {
        "func_name": "GlowBlend",
        "xref_strings": [],
        "xref_gvs": [],
        "xref_signatures": [],
        "xref_funcs": [],
        "xref_floats": ["19000.0", "0.005", "0.05"],
        "exclude_funcs": ["R_DrawTEntitiesOnList"],
    },
]
GENERATE_YAML_DESIRED_FIELDS = [
    ("GlowBlend", ["func_name", "func_sig", "func_va", "func_rva", "func_size"]),
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
