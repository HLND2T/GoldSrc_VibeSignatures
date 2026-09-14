#!/usr/bin/env python3
"""Locate BuildGammaTable through its invariant gamma-table float constants.

engine/\\view.c BuildGammaTable(float g) fills texgammatable, lightgammatable,
lineargammatable and screengammatable. The brightness-shift coefficients are
invariant across every engine family: g3 = 0.125 - brightness^2 * 0.075,
f = 0.125 + (f - g3) / (1 - g3) * 0.875, and the 1024-entry tables normalize
by 1023.0. No other function references this constant combination, so the set
is the sole positive anchor (validated unique on hl-4554/6153/8684/10210
Windows and Linux, cof-5936 Windows, and svencoop-10257 Windows). hl-10210
hw.dll reaches the pools through SSE; every other build uses x87 memory
floats, which the shared float filters also cover.

SvEngine Linux compiles the builder PIC (GOT-relative float pools) and strips
its symtab, so the constant set is not recoverable there; svencoop-10257
registers this skill for Windows only.
"""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = ["BuildGammaTable"]
FUNC_XREFS = [
    {
        "func_name": "BuildGammaTable",
        "xref_strings": [],
        "xref_gvs": [],
        "xref_signatures": [],
        "xref_funcs": [],
        "xref_floats": ["1023.0", "0.075", "0.875"],
    },
]
GENERATE_YAML_DESIRED_FIELDS = [
    ("BuildGammaTable", ["func_name", "func_sig", "func_va", "func_rva", "func_size"]),
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
