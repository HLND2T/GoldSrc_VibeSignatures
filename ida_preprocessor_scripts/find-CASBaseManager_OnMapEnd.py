#!/usr/bin/env python3
"""Locate the map-end cleanup through its active-module diagnostic.

The exact diagnostic belongs to one CASBaseManager::OnMapEnd body on each
Sven 5.15/5.16 PE32 and ELF32 input. The 5.16 map-change hook receives a map
name CString; 5.15 calls it without that argument. Publish this predecessor
as an ordinary function artifact for reuse by downstream finders.
The MSVC 5.16 SEH prologue needs the extended output-signature budget; that
signature is generated only after the diagnostic has identified the body.
"""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = ["CASBaseManager_OnMapEnd"]
FUNC_XREFS = [
    {
        "func_name": "CASBaseManager_OnMapEnd",
        "xref_strings": ["FULLMATCH:Active module was not set to null!\n"],
    },
]
GENERATE_YAML_DESIRED_FIELDS = [
    (
        "CASBaseManager_OnMapEnd",
        ["func_name", "func_va", "func_rva", "func_size", "func_sig", "func_sig_allow_across_function_boundary:true"],
    ),
]


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
        func_names=TARGET_FUNCTION_NAMES,
        func_xrefs=FUNC_XREFS,
        generate_yaml_desired_fields=GENERATE_YAML_DESIRED_FIELDS,
        debug=debug,
    )
