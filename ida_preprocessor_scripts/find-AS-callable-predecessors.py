#!/usr/bin/env python3
"""Locate array-release and variadic-call predecessors by exact owned strings.

Each selected literal has one occurrence and one owner on the requested Sven
5.15/5.16 platforms. Windows Reflection GetReturnValue has a direct variadic
callback call in its assignment conversion path. Linux ClientCommand Visit has
a direct callback invocation after the admin-rights check. Different predecessor
identities avoid the Windows inlined duplicate of that Visit diagnostic.
SetItemMappings releases its previous array and rejects/release a wrong type.
"""

from ida_analyze_util import preprocess_common_skill

PLATFORM_CALLERS = {
    "windows": {
        "func_name": "CASReflection_GetReturnValue",
        "xref_strings": [
            "FULLMATCH:CASCPPReflection::GetReturnValue: no assignment operator found for type '%s::%s', cannot convert!\n"
        ],
    },
    "linux": {
        "func_name": "CASConCommandSystem_VisitClientCommand",
        "xref_strings": ["FULLMATCH:You do not have rights needed to use this command\n"],
    },
}


async def preprocess_skill(
    session, skill_name, expected_outputs, old_yaml_map, new_binary_dir, platform, image_base, debug=False
):
    _ = skill_name, old_yaml_map
    specs = [
        {
            "func_name": "CClassicMode_SetItemMappings",
            "xref_strings": ["FULLMATCH:CClassicMode::SetItemMappings: Invalid array type passed!\n"],
        },
        PLATFORM_CALLERS[platform],
    ]
    targets = [spec["func_name"] for spec in specs]
    return await preprocess_common_skill(
        session=session,
        expected_outputs=expected_outputs,
        old_yaml_map=None,
        new_binary_dir=new_binary_dir,
        platform=platform,
        image_base=image_base,
        func_names=targets,
        func_xrefs=specs,
        generate_yaml_desired_fields=[
            (
                name,
                [
                    "func_name",
                    "func_va",
                    "func_rva",
                    "func_size",
                    "func_sig",
                    "func_sig_allow_across_function_boundary:true",
                ],
            )
            for name in targets
        ],
        debug=debug,
    )
