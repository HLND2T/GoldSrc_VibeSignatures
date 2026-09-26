#!/usr/bin/env python3
"""Locate S_Update by its own snd_show channel dump footer.

``engine/snd_dma.c`` S_Update prints ``"----(%i)----\\n"`` after listing the
active channels when ``snd_show`` is set; the debug footer is the only literal
the function owns and it resolves to exactly one function on every configured
engine build. The function itself is also the owning context the
``find-listener_origin`` global locator revalidates, so this finder runs first.
No byte signature participates in discovery.
"""

from ida_analyze_util import preprocess_common_skill

FUNC_NAME = "S_Update"
FUNC_XREFS = [{"func_name": FUNC_NAME, "xref_strings": ["FULLMATCH:----(%i)----\n"]}]
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
