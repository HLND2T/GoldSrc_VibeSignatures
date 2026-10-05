#!/usr/bin/env python3
"""Locate the console printer, excluding error handlers and callback setup."""

from pathlib import Path

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = ["Sys_Printf"]
FUNC_XREFS = [
    {
        "func_name": "Sys_Printf",
        "xref_gvs": ["Launcher_ConsolePrintf"],
        "exclude_strings": ["FATAL ERROR (shutting down): %s", "ERROR: %s"],
        # GV xrefs include the writer that initializes the callback as well.
        "exclude_funcs": ["Sys_InitGame"],
    },
]
GENERATE_YAML_DESIRED_FIELDS = [
    (
        "Sys_Printf",
        ["func_name", "func_sig", "func_va", "func_rva", "func_size", "func_sig_allow_across_function_boundary:true"],
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
    _ = skill_name, old_yaml_map
    if not new_binary_dir:
        return False
    excluded_initializers = ["Sys_InitGame"]
    for name in (
        "Sys_InitLauncherInterface",
        "Sys_SetupLegacyAPIs",
        "Launcher_ConsolePrintf_Initializer_0",
        "Launcher_ConsolePrintf_Initializer_1",
    ):
        if (Path(new_binary_dir) / f"{name}.{platform}.yaml").is_file():
            excluded_initializers.append(name)
    func_xrefs = [dict(FUNC_XREFS[0], exclude_funcs=excluded_initializers)]
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
