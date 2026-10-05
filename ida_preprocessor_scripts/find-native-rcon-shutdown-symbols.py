#!/usr/bin/env python3
"""Locate Sven shutdown entries by diagnostics owned by each function.

Host_Shutdown owns the recursive-shutdown guard and calls NET_Shutdown.
NET_Shutdown owns the threaded-networking teardown diagnostic; RunListenServer
also calls it directly before Sys_ShutdownGame on normal quit. Consumers must
therefore cover both entries, rather than relying on launcher ExitGame.
Scope: Sven 8948/10257 Windows x86 (halflife-cli issue #4 / signatures #326).
"""

from ida_analyze_util import preprocess_common_skill

NAMES = ["Host_Shutdown", "NET_Shutdown"]
FUNC_XREFS = [
    {"func_name": "Host_Shutdown", "xref_strings": ["FULLMATCH:Recursive shutdown!\n"]},
    {
        "func_name": "NET_Shutdown",
        "xref_strings": ["FULLMATCH:Threaded networking stopped successfully.\n"],
    },
]
FIELDS = ["func_name", "func_va", "func_rva", "func_size", "func_sig"]


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
    _ = skill_name, old_yaml_map
    return await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=None,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_names=NAMES,
        func_xrefs=FUNC_XREFS,
        generate_yaml_desired_fields=[(name, FIELDS) for name in NAMES],
        debug=debug,
    )
