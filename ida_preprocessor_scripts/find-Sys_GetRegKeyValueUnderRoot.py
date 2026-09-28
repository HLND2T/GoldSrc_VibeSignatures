#!/usr/bin/env python3
"""Locate the five-argument Windows registry reader in legacy HL engines.

The reader selects HKLM by the HKEY_LOCAL_MACHINE prefix and creates a String
registry key. Intersect these exact string owners; the shared helper requires one function
and generates a unique runtime signature. The filesystem language comes from
this reader, not an inlined copy of an English literal.
"""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = ["Sys_GetRegKeyValueUnderRoot"]
FUNC_XREFS = [
    {
        "func_name": "Sys_GetRegKeyValueUnderRoot",
        "xref_strings": ["FULLMATCH:HKEY_LOCAL_MACHINE", "FULLMATCH:String"],
    },
]
GENERATE_YAML_DESIRED_FIELDS = [
    ("Sys_GetRegKeyValueUnderRoot", ["func_name", "func_sig", "func_va", "func_rva", "func_size"]),
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
