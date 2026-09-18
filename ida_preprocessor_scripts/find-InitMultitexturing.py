#!/usr/bin/env python3
"""Locate SvEngine InitMultitexturing through its disable diagnostic.

SvEngine's multitexture probe prints ``Multitexturing disabled`` when the
ARB/SGIS path is not taken. The literal has exactly one owner,
InitMultitexturing, on SvEngine Linux. SvEngine Windows inlines the
probe into GL_Init (identical func_va / func_size / func_sig), so those
configs are linux-only. HL/CoF prints ``NO Multitexture extensions
found.`` from CheckMultiTextureExtensions instead, so this finder is
not registered there.
"""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = ["InitMultitexturing"]
FUNC_XREFS = [
    {
        "func_name": "InitMultitexturing",
        "xref_strings": ["FULLMATCH:Multitexturing disabled\n"],
        "xref_gvs": [],
        "xref_signatures": [],
        "xref_funcs": [],
    },
]
GENERATE_YAML_DESIRED_FIELDS = [
    ("InitMultitexturing", ["func_name", "func_sig", "func_va", "func_rva", "func_size"]),
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
