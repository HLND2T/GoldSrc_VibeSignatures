#!/usr/bin/env python3
"""Locate the Part B server owners by their own diagnostic literals.

ModelFrames checks a model index before reading sv.models. SV_LinkEdict
inserts an edict into the area tree. SV_LinkContents applies the group mask
while querying solid-edict contents. All three literals have one owner on
every configured GoldSrc, HL25, CoF and SvEngine x86 platform, including the
decrypted WON engines. Previous artifact signatures never discover them.
"""

from ida_analyze_util import preprocess_common_skill
from ida_preprocessor_scripts._server_physics_common import preserve_functions

ANCHORS = {
    "ModelFrames": "Bad sprite index!\n",
    "SV_LinkEdict": "Inserted %s with no model\n",
    "SV_LinkContents": "Invalid contents on trigger field: %s\n",
}
FIELDS = ["func_name", "func_va", "func_rva", "func_size", "func_sig", "func_sig_allow_across_function_boundary:true"]


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
    found = await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=None,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_names=list(ANCHORS),
        func_xrefs=[{"func_name": name, "xref_strings": ["FULLMATCH:" + literal]} for name, literal in ANCHORS.items()],
        generate_yaml_desired_fields=[(name, FIELDS) for name in ANCHORS],
        debug=debug,
    )

    return found and await preserve_functions(session, expected_outputs, platform, image_base, list(ANCHORS))
