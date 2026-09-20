#!/usr/bin/env python3
"""Locate Draw_TextureMode_f, the gl_texturemode handler, from its own literal.

The handler owns the "bad filter name" diagnostic on every classic GoldSrc /
HL25 / CoF / BLOB engine. SvEngine replaced the whole textual set, so its
handler is the only owner of "Invalid filter name" instead; the classic literal
does not exist there and must never be used as a fallback.

Only the anchor literal differs per family; output identity, platform gating and
the discovery contract are identical, so both families are served by this one
script. Discovery never consumes an old artifact signature.

On SvEngine the handler has code xrefs but no owning function in the IDB, so its
entry is recovered from the ``Cmd_AddCommand`` registration before the shared
string-owner walk runs. See ``_engine_texture_mode_common``.
"""

from pathlib import Path

from ida_analyze_util import preprocess_common_skill
from ida_preprocessor_scripts._engine_texture_mode_common import recover_registered_owner

TARGET_FUNCTION_NAME = "Draw_TextureMode_f"
CLASSIC_LITERAL = "bad filter name\n"
SVENGINE_LITERAL = "Invalid filter name\n"
FUNC_FIELDS = ["func_name", "func_sig", "func_va", "func_rva", "func_size"]


def _anchor_literal(new_binary_dir):
    gamever = Path(new_binary_dir).resolve().parent.name
    if gamever.startswith("svencoop-"):
        return SVENGINE_LITERAL
    return CLASSIC_LITERAL


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
    literal = _anchor_literal(new_binary_dir)
    await recover_registered_owner(session, literal, debug)
    func_xrefs = [
        {
            "func_name": TARGET_FUNCTION_NAME,
            "xref_strings": [f"FULLMATCH:{literal}"],
            "xref_gvs": [],
            "xref_signatures": [],
            "xref_funcs": [],
        },
    ]
    return await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=None,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_names=[TARGET_FUNCTION_NAME],
        func_xrefs=func_xrefs,
        generate_yaml_desired_fields=[(TARGET_FUNCTION_NAME, FUNC_FIELDS)],
        debug=debug,
    )
