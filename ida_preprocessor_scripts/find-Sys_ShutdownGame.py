#!/usr/bin/env python3
"""Locate Sys_ShutdownGame through its TRACESHUTDOWN wrapper string.

Sys_ShutdownGame (engine/sys_dll2.cpp) is the shutdown path that runs
TRACESHUTDOWN(Sys_ShutdownLauncherInterface()), ..., TRACESHUTDOWN(Sys_Shutdown()).
The TRACESHUTDOWN macro stringifies its argument, so the exact C literal
"Sys_Shutdown()" is referenced inside Sys_ShutdownGame's own body.

The same literal is also referenced by Sys_InitGame, which stringifies the
TRACEINIT(initfunc, shutdownfunc) pair as ("Sys_Init()", "Sys_Shutdown()"). That
second owner is excluded by the "Sys_Init()" literal, which Sys_InitGame owns
and Sys_ShutdownGame never references. Both anchors are exact C strings, so
"Sys_Shutdown()" cannot match "Sys_ShutdownMemory()" and vice versa.

Discovery uses the shared string-xref intersection only; no byte signature, no
prior artifact and no LLM output participates in locating the function.
"""

from ida_analyze_util import preprocess_common_skill


TARGET_FUNCTION_NAMES = ["Sys_ShutdownGame"]

ANCHOR_STRING = "FULLMATCH:Sys_Shutdown()"
INIT_GAME_STRING = "FULLMATCH:Sys_Init()"

GENERATE_YAML_DESIRED_FIELDS = [
    (
        "Sys_ShutdownGame",
        ["func_name", "func_sig", "func_va", "func_rva", "func_size"],
    ),
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
    _ = skill_name
    if platform not in {"windows", "linux"}:
        return False
    func_xrefs = [
        {
            "func_name": "Sys_ShutdownGame",
            "xref_strings": [ANCHOR_STRING],
            "xref_gvs": [],
            "xref_signatures": [],
            "xref_funcs": [],
            "exclude_funcs": [],
            "exclude_strings": [INIT_GAME_STRING],
            "exclude_gvs": [],
            "exclude_signatures": [],
        },
    ]
    return await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=None,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_names=TARGET_FUNCTION_NAMES,
        func_xrefs=func_xrefs,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )
