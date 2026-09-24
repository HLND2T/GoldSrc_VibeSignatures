#!/usr/bin/env python3
"""Locate VOX_LoadSound by its own missing-sentence diagnostic.

``VOX_LoadSound`` prints ``"VOX_LoadSound: no sentence named %s\\n"`` when the
sentence lookup fails (``snd_mix.c``). The exact literal occurs once in every
configured engine build and all of its references belong to this function.
"""

from ida_analyze_util import preprocess_common_skill

FUNC_NAME = "VOX_LoadSound"
FUNC_XREFS = [{"func_name": FUNC_NAME, "xref_strings": ["FULLMATCH:VOX_LoadSound: no sentence named %s\n"]}]
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
