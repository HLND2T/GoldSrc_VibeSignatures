#!/usr/bin/env python3
"""Locate CL_ReallocateDynamicData through its own diagnostic/name literal.

Owns allocation and publication of the dynamic client entity array.
Discovery never consumes an old artifact signature.
"""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = ["CL_ReallocateDynamicData"]
FUNC_XREFS = [
    {
        "func_name": "CL_ReallocateDynamicData",
        "xref_strings": ["FULLMATCH:CL_Reallocate cl_entities\n"],
        "xref_gvs": [],
        "xref_signatures": [],
        "xref_funcs": [],
        # GCC also inlines this allocator into resource/serverinfo handling.
        "exclude_strings": [
            "FULLMATCH:Setting up renderer...\n",
            "FULLMATCH:Serverinfo packet received.\n",
        ],
    },
]
GENERATE_YAML_DESIRED_FIELDS = [
    ("CL_ReallocateDynamicData", ["func_name", "func_sig", "func_va", "func_rva", "func_size"]),
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
