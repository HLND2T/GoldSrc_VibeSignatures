#!/usr/bin/env python3
"""Locate GL_LoadTexture2 through its allocator-exhaustion literals.

GL_LoadTexture2 owns the ``gltextures`` overflow diagnostic
(engine/gl_rmisc.c). Most validated branches print ``Texture
Overflow: MAX_GLTEXTURES`` when the texture array is full, while the
SvEngine Windows build instead reports ``NULL Texture`` when the wrapper
returns without a slot. Each literal has exactly one owner, GL_LoadTexture2,
on its validated builds, so the two specs are tried in order and the first
single-owner match wins. The hl-10210 and svencoop-10257 Linux branches are
not covered here: their producers run through the dedicated
find-Draw_MiptexTexture-decompiles / find-DT_LoadDetailTexture-decompiles
chains and this skill is platform-gated to Windows in those configs.
"""

from ida_analyze_util import preprocess_common_skill

TARGET_FUNCTION_NAMES = ["GL_LoadTexture2"]
FUNC_XREFS_SPECS = [
    [
        {
            "func_name": "GL_LoadTexture2",
            "xref_strings": ["FULLMATCH:Texture Overflow: MAX_GLTEXTURES"],
            "xref_gvs": [],
            "xref_signatures": [],
            "xref_funcs": [],
        },
    ],
    [
        {
            "func_name": "GL_LoadTexture2",
            "xref_strings": ["FULLMATCH:NULL Texture\n"],
            "xref_gvs": [],
            "xref_signatures": [],
            "xref_funcs": [],
        },
    ],
]
GENERATE_YAML_DESIRED_FIELDS = [
    ("GL_LoadTexture2", ["func_name", "func_sig", "func_va", "func_rva", "func_size"]),
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
