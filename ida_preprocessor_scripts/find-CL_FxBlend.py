#!/usr/bin/env python3
"""Locate CL_FxBlend through its own invariant effect coefficients.

engine/cl_tent.c uses 363.0 to de-sync effects by entity number, 20 for
strobe/flicker amplitude, and 16 for fast pulse amplitude and effect frequency.
Require all three numeric values in the same function through the shared
width-aware f32/f64 SSE/x87 constant reader, including recorded PIC data xrefs.
Discovery never uses an old artifact signature or a predecessor function.

Validated on all 13 configured engine/platform pairs: hl-3248/3266/3329/3647/
4554/6153/8684/10210, cof-5936, and svencoop-10257 (Linux where shipped).
Every generated artifact matches the previous accessor-based locator exactly.
"""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = ["CL_FxBlend"]
FUNC_XREFS = [
    {
        "func_name": "CL_FxBlend",
        "xref_strings": [],
        "xref_gvs": [],
        "xref_signatures": [],
        "xref_funcs": [],
        "xref_floats": ["363.0", "20.0", "16.0"],
    },
]
GENERATE_YAML_DESIRED_FIELDS = [
    ("CL_FxBlend", ["func_name", "func_sig", "func_va", "func_rva", "func_size"]),
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
