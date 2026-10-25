#!/usr/bin/env python3
"""Locate the server area walker and checked entity-number conversion.

Both diagnostics belong to their own function, including SvEngine's inlined
physent conversion. Never discover a function through an old artifact signature.
"""

from ida_analyze_util import preprocess_common_skill
from ida_preprocessor_scripts._server_physent_common import preserve_functions

ANCHORS = {
    "SV_AddLinksToPM_": "SV_AddLinksToPM:  pmove->numphysent >= MAX_PHYSENTS\n",
    "NUM_FOR_EDICT": "NUM_FOR_EDICT: bad pointer",
}
FIELDS = ["func_name", "func_va", "func_rva", "func_size", "func_sig", "func_sig_allow_across_function_boundary:true"]


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
    _ = skill_name, old_yaml_map
    found = await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=None,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_names=list(ANCHORS),
        func_xrefs=[
            {
                "func_name": name,
                "xref_strings": ["FULLMATCH:" + literal],
                # The entity-to-client helper inlines NUM_FOR_EDICT's check.
                "exclude_strings": ["FULLMATCH:Entity is not a client"] if name == "NUM_FOR_EDICT" else [],
            }
            for name, literal in ANCHORS.items()
        ],
        generate_yaml_desired_fields=[(name, FIELDS) for name in ANCHORS],
        debug=debug,
    )
    return found and await preserve_functions(session, expected_outputs, platform, image_base, list(ANCHORS))
