#!/usr/bin/env python3
"""Locate S_StartStaticSound by its own pitch-zero diagnostic.

``engine/snd_dma.c`` S_StartStaticSound prints
``"Warning: S_StartStaticSound Ignored, called with pitch 0"`` (``Con_DPrintf``)
when a static sound is requested with pitch 0; unlike the dynamic variant GCC
never clones this body, so the literal resolves to exactly one function on
every configured engine build. No byte signature participates in discovery.
"""

from ida_analyze_util import preprocess_common_skill

FUNC_NAME = "S_StartStaticSound"
FUNC_XREFS = [
    {"func_name": FUNC_NAME, "xref_strings": ["FULLMATCH:Warning: S_StartStaticSound Ignored, called with pitch 0"]}
]
FUNC_FIELDS = [(FUNC_NAME, ["func_name", "func_sig", "func_va", "func_rva", "func_size"])]


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
