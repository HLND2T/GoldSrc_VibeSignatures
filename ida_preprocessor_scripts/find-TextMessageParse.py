#!/usr/bin/env python3
"""Locate TextMessageParse by its own message-count guard.

``engine/tmessage.c`` TextMessageParse calls
``Sys_Error("tmessage::TextMessageParse : messageCount>=MAX_MESSAGES")``
inside its ``titles.txt`` line loop; the fully qualified diagnostic is owned by
exactly one function on every configured engine build. Its caller
``TextMessageInit`` loads ``titles.txt`` but owns no copy of the literal, so no
predecessor chain is needed. No byte signature participates in discovery.
"""

from ida_analyze_util import preprocess_common_skill

FUNC_NAME = "TextMessageParse"
FUNC_XREFS = [
    {
        "func_name": FUNC_NAME,
        "xref_strings": ["FULLMATCH:tmessage::TextMessageParse : messageCount>=MAX_MESSAGES"],
    }
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
