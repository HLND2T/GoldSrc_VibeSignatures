#!/usr/bin/env python3
"""Locate R_DrawParticles through its particle-scale float constants.

engine/r_part.c R_DrawParticles keeps the GLQUAKE sprite-scale hack

    if (scale < 20)
        scale = 1;
    else
        scale = 1 + scale * 0.004;

inside its own body. ``20`` is compared as a float constant while the C
literal ``0.004`` is double and therefore stored as an 8-byte constant; the
function referencing both constants is unique on every validated engine build
(GoldSrc, HL25, SvEngine and CoF, Windows and Linux alike).
"""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = ["R_DrawParticles"]
FUNC_XREFS = [
    {
        "func_name": "R_DrawParticles",
        "xref_strings": [],
        "xref_gvs": [],
        "xref_signatures": [],
        "xref_funcs": [],
        "xref_floats": ["20.0", "0.004"],
    },
]
GENERATE_YAML_DESIRED_FIELDS = [
    ("R_DrawParticles", ["func_name", "func_sig", "func_va", "func_rva", "func_size"]),
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
