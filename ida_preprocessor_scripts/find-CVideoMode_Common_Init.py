#!/usr/bin/env python3
"""Locate CVideoMode_Common_Init for the non-HL25 startup-graphic chain.

engine/vid_common.cpp CVideoMode_Common::Init parses the ``-forceres`` or the
older ``-24bpp`` command line; each literal has exactly one owner, Init, on
its validated builds. HL25 Init does not call the startup graphic directly, so
HL25 registers this predecessor through PlayStartupSequence instead. The specs
are tried in order and the first single-owner match wins.
"""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = ["CVideoMode_Common_Init"]
FUNC_XREFS_SPECS = [
    [
        {
            "func_name": "CVideoMode_Common_Init",
            "xref_strings": ["FULLMATCH:-forceres"],
            "xref_gvs": [],
            "xref_signatures": [],
            "xref_funcs": [],
        },
    ],
    [
        {
            "func_name": "CVideoMode_Common_Init",
            "xref_strings": ["FULLMATCH:-24bpp"],
            "xref_gvs": [],
            "xref_signatures": [],
            "xref_funcs": [],
        },
    ],
]
GENERATE_YAML_DESIRED_FIELDS = [
    ("CVideoMode_Common_Init", ["func_name", "func_sig", "func_va", "func_rva", "func_size"]),
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
    for func_xrefs in FUNC_XREFS_SPECS:
        if await preprocess_common_skill(
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
        ):
            return True
    return False
