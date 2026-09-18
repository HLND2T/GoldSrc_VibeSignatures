#!/usr/bin/env python3
"""Locate DT_LoadDetailMapFile, the engine detail-texture mapping loader.

engine/DetailTexture.cpp DT_LoadDetailMapFile is the only function that reports
a missing per-level detail mapping file by name.  Its first statement reads
``detTexSupported`` and it is a standalone function on every engine family,
including the BLOB builds where DT_Initialize itself was inlined into
GL_MultiTexInit, so it is the predecessor for that global.
"""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = ["DT_LoadDetailMapFile"]
FUNC_XREFS = [
    {
        "func_name": "DT_LoadDetailMapFile",
        "xref_strings": ["FULLMATCH:No detail texture mapping file: %s\n"],
        "xref_gvs": [],
        "xref_signatures": [],
        "xref_funcs": [],
    },
]
GENERATE_YAML_DESIRED_FIELDS = [
    ("DT_LoadDetailMapFile", ["func_name", "func_sig", "func_va", "func_rva", "func_size"]),
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
