#!/usr/bin/env python3
"""Locate R_LoadSkyboxInt_SvEngine through its single-space sky-face banner.

The classic hl/CoF/HL25 loader prints ``SKY:  `` (two trailing spaces) and is
covered by ``find-R_LoadSkys``.  SvEngine keeps the six sky faces in an
internal loader that prints ``SKY: `` (one trailing space, no newline); that
literal has exactly one owning function on every verified SvEngine build
(svencoop-10257/8948, Windows and Linux) and that function is the
``R_LoadSkyboxInt(char const*)`` that ``R_LoadSkyBox_SvEngine`` calls.  The
exact match keeps the one-space SvEngine form distinct from the two-space
family literal, so this finder must never be registered for hl/CoF.
"""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = ["R_LoadSkyboxInt_SvEngine"]
FUNC_XREFS = [
    {
        "func_name": "R_LoadSkyboxInt_SvEngine",
        "xref_strings": ["FULLMATCH:SKY: "],
        "xref_gvs": [],
        "xref_signatures": [],
        "xref_funcs": [],
    },
]
GENERATE_YAML_DESIRED_FIELDS = [
    (
        "R_LoadSkyboxInt_SvEngine",
        ["func_name", "func_sig", "func_va", "func_rva", "func_size"],
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
