#!/usr/bin/env python3
"""Locate SvEngine V_BuildGammaTable through the gamma-table float constants.

SvEngine compiles the view.c builder as V_BuildGammaTable (Linux
``_Z17V_BuildGammaTablef``; the Windows body is the same function). The
brightness-shift coefficients are invariant: g3 = 0.125 - brightness^2 * 0.075,
f = 0.125 + (f - g3) / (1 - g3) * 0.875, and the 1024-entry tables normalize
by 1023.0. No other function references this constant combination, including
on PIC Linux where the pools are GOT-relative.

GoldSrc/HL25/CoF keep emitting BuildGammaTable via find-BuildGammaTable.
"""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = ["V_BuildGammaTable"]
FUNC_XREFS = [
    {
        "func_name": "V_BuildGammaTable",
        "xref_strings": [],
        "xref_gvs": [],
        "xref_signatures": [],
        "xref_funcs": [],
        "xref_floats": ["1023.0", "0.075", "0.875"],
    },
]
GENERATE_YAML_DESIRED_FIELDS = [
    ("V_BuildGammaTable", ["func_name", "func_sig", "func_va", "func_rva", "func_size"]),
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
